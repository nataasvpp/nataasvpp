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
