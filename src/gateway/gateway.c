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
      pool_init_fixed (ptd->output,
		       1ULL << (VCDP_LOG2_SESSIONS_PER_THREAD + 1));
    }
  pool_init_fixed (gm->tenants, 1ULL << VCDP_LOG2_TENANTS);

  done = 1;
}

static clib_error_t *
gateway_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (gateway_init);
