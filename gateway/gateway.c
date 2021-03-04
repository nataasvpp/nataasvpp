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

#define _GNU_SOURCE
#include <sys/mman.h>

#include <gateway/gateway.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

gw_main_t gateway_main;

static void
gateway_enable_one (vlib_main_t *vm, vnet_main_t *vnm, gw_main_t *gm,
		    u32 rx_sw_if_index, u32 tx_sw_if_index)
{
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, tx_sw_if_index);
  u16 next_index =
    vlib_node_add_next (vm, gw_counter_node.index, hi->output_node_index);
  vec_validate_init_empty (gm->tx_sw_if_index_by_rx_sw_if_index,
			   rx_sw_if_index, ~0);
  vec_validate_init_empty (gm->next_index_by_rx_sw_if_index, rx_sw_if_index,
			   ~0);
  gm->next_index_by_rx_sw_if_index[rx_sw_if_index] = next_index;
  gm->tx_sw_if_index_by_rx_sw_if_index[rx_sw_if_index] = tx_sw_if_index;
}

int
gateway_enable_disable (gw_main_t *gm, u32 sw_if_index1, u32 sw_if_index2,
			int enable_disable)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  if (!vnet_sw_interface_is_valid (vnm, sw_if_index1))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  if (!vnet_sw_interface_is_valid (vnm, sw_if_index2))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (gm->per_thread_data == 0)
    {
      /* initialize per-thrad pools */
      vlib_thread_main_t *tm = vlib_get_thread_main ();
      vec_validate (gm->per_thread_data, tm->n_vlib_mains - 1);
      for (int i = 0; i < tm->n_vlib_mains; i++)
	{
	  gw_per_thread_data_t *ptd =
	    vec_elt_at_index (gm->per_thread_data, i);
	  pool_init_fixed (ptd->flows, 1ULL << GW_LOG2_FLOWS_PER_THREAD);
	}

      gm->frame_queue_index =
	vlib_frame_queue_main_init (gw_counter_node.index, 0);
    }

  if (enable_disable)
    {
      if (gm->table4.nbuckets == 0)
	clib_bihash_init_24_8 (&gm->table4, "gateway ipv4",
			       BIHASH_IP4_NUM_BUCKETS, BIHASH_IP4_MEM_SIZE);

      gateway_enable_one (vm, vnm, gm, sw_if_index1, sw_if_index2);
      gateway_enable_one (vm, vnm, gm, sw_if_index2, sw_if_index1);
    }
  else
    return VNET_API_ERROR_UNIMPLEMENTED;
  return 0;
}

static clib_error_t *
gateway_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  gw_main_t *sm = &gateway_main;
  u32 sw_if_index1 = ~0;
  u32 sw_if_index2 = ~0;
  int enable_disable = 1;
  int rv;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U %U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index1, unformat_vnet_sw_interface, vnm,
			 &sw_if_index2))
	;
      else
	break;
    }

  if (sw_if_index1 == ~0 || sw_if_index2 == ~0)
    return clib_error_return (0, "Please specify an interface...");
  rv = gateway_enable_disable (sm, sw_if_index1, sw_if_index2, enable_disable);
  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "Invalid interface");
      break;
    default:
      return clib_error_return (0, "gateway_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gateway_enable_disable_command, static) = {
  .path = "gateway",
  .short_help = "gateway <interface-name> <interface-name> [disable]",
  .function = gateway_enable_disable_command_fn,
};
/* *INDENT-ON* */

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
      vlib_cli_output (vm, "Thread %u: %u flows\n", ptd - gm->per_thread_data,
		       pool_elts (ptd->flows));
      if (verbose)
	pool_foreach_index (i, ptd->flows)
	  {
	    gw_flow_t *f = pool_elt_at_index (ptd->flows, i);
	    vlib_cli_output (vm, "%7u: %U\n", i, format_gw_flow, f);
	  }
    }

  return 0;
}

VLIB_CLI_COMMAND (show_flow_handoff, static) = {
  .path = "show vcdp gateway",
  .short_help = "show vcdp gateway",
  .function = show_gateway_command_fn,
};

static clib_error_t *
gateway_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (gateway_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VCDP_GW_PLUGIN_BUILD_VER,
  .description = "vCDP Gateway Plugin",
};
/* *INDENT-ON* */
