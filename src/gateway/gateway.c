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

__clib_unused static void
gateway_init_main_if_needed (gw_main_t *gm)
{
  static u32 done = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  if (done)
    return;

  /* initialize per-thread pools */
  vec_validate (gm->per_thread_data, tm->n_vlib_mains - 1);
  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      gw_per_thread_data_t *ptd = vec_elt_at_index (gm->per_thread_data, i);
      vec_validate (ptd->output, 1ULL << (VCDP_LOG2_SESSIONS_PER_THREAD + 1));
    }
  vec_validate (gm->tenants, 1ULL << VCDP_LOG2_TENANTS);

  done = 1;
}

static clib_error_t *
gateway_init (vlib_main_t *vm)
{
  return 0;
}

void
gw_enable_disable_geneve_input (gw_enable_disable_geneve_input_args_t *args)
{
  gw_main_t *gm = &gateway_main;
  int rv = 0;
  gateway_init_main_if_needed (gm);
  rv = vnet_feature_enable_disable ("ip4-unicast", "vcdp-geneve-input",
				    args->sw_if_index, args->enable_disable, 0,
				    0);
  args->rv = rv;
  if (rv)
    args->err = clib_error_return (
      0, "Failed vnet_feature_enable_disable with error %d : %U", rv,
      format_vnet_api_errno, rv);
  else
    args->err = 0;
}

void
gw_set_geneve_output (gw_set_geneve_output_args_t *args)
{
  gw_main_t *gm = &gateway_main;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tenant_t *vt;
  gw_tenant_t *gt;
  clib_bihash_kv_8_8_t kv = {};
  u8 dir = !!args->direction;
  kv.key = args->tenant_id;
  if (clib_bihash_search_inline_8_8 (&vcdp->tenant_idx_by_id, &kv))
    {
      args->rv = -1;
      args->err =
	clib_error_return (0, "tenant-id %d not found", args->tenant_id);
      return;
    }
  vt = vcdp_tenant_at_index (vcdp, kv.value);
  gt = gw_tenant_at_index (gm, kv.value);

  /* Caching tenant id in gt */
  gt->tenant_id = vt->tenant_id;
  gt->flags |= GW_TENANT_F_OUTPUT_DATA_SET;
  gt->geneve_src_ip[dir] = args->src_addr;
  gt->geneve_dst_ip[dir] = args->dst_addr;
  gt->geneve_src_port[dir] = args->src_port;
  gt->geneve_dst_port[dir] = args->dst_port;

  args->rv = 0;
  args->err = 0;
}

VLIB_INIT_FUNCTION (gateway_init);
