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
#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vcdp/tcp-check/tcp_check.h>

static clib_error_t *
vcdp_tcp_check_show_sessions_command_fn (vlib_main_t *vm,
					 unformat_input_t *input,
					 vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tcp_check_main_t *vtcm = &vcdp_tcp;
  vcdp_per_thread_data_t *ptd;
  vcdp_tcp_check_per_thread_data_t *vptd;
  vcdp_session_t *session;
  vcdp_tcp_check_session_state_t *tcp_session;
  u32 thread_index;
  u32 session_index;
  u32 tenant_id = ~0;
  u8 first;
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
	vptd = vec_elt_at_index (vtcm->ptd, thread_index);
	first = 1;
	pool_foreach_index (session_index, ptd->sessions)
	  {
	    session = vcdp_session_at_index (ptd, session_index);
	    if (tenant_id != ~0 && tenant_id != session->key.tenant_id)
	      continue;
	    if (session->key.ip4_key.proto != IP_PROTOCOL_TCP)
	      continue;
	    if (first)
	      {
		first = 0;
		vlib_cli_output (vm, "Thread #%d:", thread_index);
		vlib_cli_output (vm, "id\t\t\ttenant\tindex\ttype\t"
				     "ingress\t\t\t-> egress\t\tflags");
	      }
	    tcp_session = vec_elt_at_index (vptd->state, session_index);
	    vlib_cli_output (vm, "%U", format_vcdp_tcp_check_session,
			     session_index, session, tcp_session);
	  }
      }

  return err;
}

VLIB_CLI_COMMAND (show_vcdp_tcp_check_sessions_command, static) = {
  .path = "show vcdp tcp session-table",
  .short_help = "show vcdp tcp session-table [tenant <tenant-id>]",
  .function = vcdp_tcp_check_show_sessions_command_fn,
};