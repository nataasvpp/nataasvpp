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

#include <vcdp/vcdp.h>

#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

vcdp_main_t vcdp_main;

static void
vcdp_timer_expired (u32 *expired)
{
  u32 *e;
  uword thread_index = vlib_get_thread_index ();
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd =
    vec_elt_at_index (vcdp->per_thread_data, thread_index);
  vec_foreach (e, expired)
    {
      u32 session_idx = e[0] & VCDP_TIMER_SI_MASK;
      vec_add1 (ptd->expired_sessions, session_idx);
    }
}

static void
vcdp_init_main_if_needed (vcdp_main_t *vcdp)
{
  static u32 done = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  if (done)
    return;
  time_t epoch = time (NULL);
  uword log_n_thread = max_log2 (tm->n_vlib_mains);
  uword template_shift =
    VCDP_SESSION_ID_TOTAL_BITS - VCDP_SESSION_ID_EPOCH_N_BITS - log_n_thread;
  vcdp->session_id_ctr_mask = (((u64) 1 << template_shift) - 1);
  /* initialize per-thread data */
  vec_validate (vcdp->per_thread_data, tm->n_vlib_mains - 1);
  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      vcdp_per_thread_data_t *ptd =
	vec_elt_at_index (vcdp->per_thread_data, i);
      pool_init_fixed (ptd->sessions, 1ULL << VCDP_LOG2_SESSIONS_PER_THREAD);
      /* fixed pools are already zeroed (mmap) */
      vcdp_tw_init (&ptd->wheel, vcdp_timer_expired, VCDP_TIMER_INTERVAL, ~0);
      ptd->session_id_template = (u64) epoch
				 << (template_shift + log_n_thread);
      ptd->session_id_template |= (u64) i << template_shift;
    }

  pool_init_fixed (vcdp->tenants, 1ULL << VCDP_LOG2_TENANTS);
  clib_bihash_init_24_8 (&vcdp->table4, "vcdp ipv4 session table",
			 BIHASH_IP4_NUM_BUCKETS, BIHASH_IP4_MEM_SIZE);
  clib_bihash_init_8_8 (&vcdp->tenant_idx_by_id, "vcdp tenant table",
			BIHASH_TENANT_NUM_BUCKETS, BIHASH_TENANT_MEM_SIZE);
  clib_bihash_init_8_8 (&vcdp->session_index_by_id, "session idx by id",
			BIHASH_IP4_NUM_BUCKETS, BIHASH_IP4_MEM_SIZE);

  vcdp->frame_queue_index =
    vlib_frame_queue_main_init (vcdp_handoff_node.index, 0);
  done = 1;
}

static clib_error_t *
vcdp_init (vlib_main_t *vm)
{
  return 0;
}

static void
vcdp_enable_disable_timer_expire_node (u8 is_disable)
{
  vlib_main_t *vm;
  u32 n_vms = vlib_num_workers () + 1;
  for (int i = 1; i < n_vms; i++)
    {
      vm = vlib_mains[i];
      vlib_node_t *node =
	vlib_get_node_by_name (vm, (u8 *) "vcdp-timer-expire");
      vlib_node_set_state (vm, node->index,
			   is_disable ? VLIB_NODE_STATE_DISABLED :
					VLIB_NODE_STATE_POLLING);
    }
}

clib_error_t *
vcdp_tenant_add_del (vcdp_main_t *vcdp, u32 tenant_id, u8 is_del)
{
  vcdp_init_main_if_needed (vcdp);
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  clib_error_t *err = 0;
  vcdp_tenant_t *tenant;
  u32 tenant_idx;
  u32 n_tenants = pool_elts (vcdp->tenants);
  if (!is_del)
    {
      if (clib_bihash_search_inline_8_8 (&vcdp->tenant_idx_by_id, &kv))
	{
	  pool_get (vcdp->tenants, tenant);
	  tenant_idx = tenant - vcdp->tenants;
	  tenant->bitmaps[VCDP_FLOW_FORWARD] = VCDP_DEFAULT_BITMAP;
	  tenant->bitmaps[VCDP_FLOW_BACKWARD] = VCDP_DEFAULT_BITMAP;
	  tenant->tenant_id = tenant_id;
	  kv.key = tenant_id;
	  kv.value = tenant_idx;
	  clib_bihash_add_del_8_8 (&vcdp->tenant_idx_by_id, &kv, 1);
	}
      else
	{
	  err = clib_error_return (0,
				   "Can't create tenant with id %d"
				   " (already exists with index %d)",
				   tenant_id, kv.value);
	}
    }
  else
    {
      if (clib_bihash_search_inline_8_8 (&vcdp->tenant_idx_by_id, &kv))
	{
	  err = clib_error_return (0,
				   "Can't delete tenant with id %d"
				   " (not found)",
				   tenant_id);
	}
      else
	{
	  pool_put_index (vcdp->tenants, kv.value);
	  clib_bihash_add_del_8_8 (&vcdp->tenant_idx_by_id, &kv, 0);
	  /* TODO: Notify other users of "tenants" (like gw)?
	   * maybe cb list? */
	}
    }
  if (!err && ((n_tenants == 1 && is_del) || (n_tenants == 0 && !is_del)))
    vcdp_enable_disable_timer_expire_node (is_del);
  return err;
}

clib_error_t *
vcdp_set_services (vcdp_main_t *vcdp, u32 tenant_id, u32 bitmap, u8 direction)
{
  vcdp_init_main_if_needed (vcdp);
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  vcdp_tenant_t *tenant;
  if (clib_bihash_search_inline_8_8 (&vcdp->tenant_idx_by_id, &kv))
    return clib_error_return (
      0, "Can't assign service map: tenant id %d not found", tenant_id);

  tenant = vcdp_tenant_at_index (vcdp, kv.value);
  tenant->bitmaps[direction] = bitmap;
  return 0;
}

VLIB_INIT_FUNCTION (vcdp_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VCDP_GW_PLUGIN_BUILD_VER,
  .description = "vCDP Gateway Plugin",
};
