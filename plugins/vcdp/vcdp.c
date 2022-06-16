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

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.c>

#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_template.c>

#include <vcdp/vcdp.h>
#include <vcdp/service.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include <vnet/ip/reass/ip4_sv_reass.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vcdp/service.h>
#define VCDP_DEFAULT_BITMAP VCDP_SERVICE_MASK (drop)

VCDP_SERVICE_DECLARE (drop)

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
vcdp_init_ptd_counters (vcdp_per_thread_data_t *ptd, uword i)
{
#define _(x, y)                                                               \
  u8 *name = format (0, y "_%d", i);                                          \
  u8 *stat_seg_name = format (0, "/vcdp/per_flow_counters/" y "/%d%c", i, 0); \
  ptd->per_session_ctr[VCDP_FLOW_COUNTER_##x].name = (char *) name;           \
  ptd->per_session_ctr[VCDP_FLOW_COUNTER_##x].stat_segment_name =             \
    (char *) stat_seg_name;                                                   \
  vlib_validate_combined_counter (                                            \
    &ptd->per_session_ctr[VCDP_FLOW_COUNTER_##x],                             \
    1ULL << (1 + VCDP_LOG2_SESSIONS_PER_THREAD));

  foreach_vcdp_flow_counter
#undef _
}

static void
vcdp_init_tenant_counters (vcdp_main_t *vcdp)
{
#define _(x, y, z)                                                            \
  vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x].name = y;         \
  vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x]                   \
    .stat_segment_name = "/vcdp/per_tenant_counters/" y;                      \
  vlib_validate_simple_counter (                                              \
    &vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x],               \
    1ULL << (1 + VCDP_LOG2_TENANTS));

  foreach_vcdp_tenant_session_counter
#undef _
#define _(x, y, z)                                                            \
  vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x].name = y;               \
  vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x].stat_segment_name =     \
    "/vcdp/per_tenant_counters/" y;                                           \
  vlib_validate_combined_counter (                                            \
    &vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x],                     \
    1ULL << (1 + VCDP_LOG2_TENANTS));

    foreach_vcdp_tenant_data_counter
#undef _
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
      vcdp_tw_init (&ptd->wheel, vcdp_timer_expired, VCDP_TIMER_INTERVAL, ~0);
      ptd->session_id_template = (u64) epoch
				 << (template_shift + log_n_thread);
      ptd->session_id_template |= (u64) i << template_shift;
      vcdp_init_ptd_counters (ptd, i);
    }
  pool_init_fixed (vcdp->tenants, 1ULL << VCDP_LOG2_TENANTS);
  vcdp_init_tenant_counters (vcdp);
  clib_bihash_init_24_8 (&vcdp->table4, "vcdp ipv4 session table",
			 BIHASH_IP4_NUM_BUCKETS, BIHASH_IP4_MEM_SIZE);
  clib_bihash_init_48_8 (&vcdp->table6, "vcdp ipv6 session table",
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
  vcdp_main_t *vcdp = &vcdp_main;
  vlib_call_init_function (vm, vcdp_service_init);
  vcdp_service_next_indices_init (vm, vcdp_lookup_ip4_node.index);
  vcdp_service_next_indices_init (vm, vcdp_lookup_ip6_node.index);
  vcdp_service_next_indices_init (vm, vcdp_handoff_node.index);
  vcdp->ip4_sv_reass_next_index =
    ip4_sv_reass_custom_context_register_next_node (
      vcdp_lookup_ip4_node.index);
  return 0;
}

static void
vcdp_enable_disable_timer_expire_node (u8 is_disable)
{
  vlib_main_t *vm;
  u32 n_vms = vlib_num_workers () + 1;
  /* Maybe disable main thread if workers are present */
  for (int i = 0; i < n_vms; i++)
    {
      vm = vlib_get_main_by_index (i);
      vlib_node_t *node =
	vlib_get_node_by_name (vm, (u8 *) "vcdp-timer-expire");
      vlib_node_set_state (vm, node->index,
			   is_disable ? VLIB_NODE_STATE_DISABLED :
					      VLIB_NODE_STATE_POLLING);
    }
}

void
vcdp_tenant_clear_counters (vcdp_main_t *vcdp, u32 tenant_idx)
{
#define _(x, y, z)                                                            \
  vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x].name = y;         \
  vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x]                   \
    .stat_segment_name = "/vcdp/per_tenant_counters/" y;                      \
  vlib_zero_simple_counter (                                                  \
    &vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x], tenant_idx);

  foreach_vcdp_tenant_session_counter
#undef _
#define _(x, y, z)                                                            \
  vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x].name = y;               \
  vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x].stat_segment_name =     \
    "/vcdp/per_tenant_counters/" y;                                           \
  vlib_zero_combined_counter (                                                \
    &vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x], tenant_idx);

    foreach_vcdp_tenant_data_counter
#undef _
}

static void
vcdp_tenant_init_timeouts (vcdp_tenant_t *tenant)
{
#define _(x, y, z) tenant->timeouts[VCDP_TIMEOUT_##x] = y;
  foreach_vcdp_timeout
#undef _
}

static void
vcdp_tenant_init_sp_nodes (vcdp_tenant_t *tenant)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_t *node;

#define _(sym, default, str)                                                  \
  node = vlib_get_node_by_name (vm, (u8 *) (default));                        \
  tenant->sp_node_indices[VCDP_SP_NODE_##sym] = node->index;

  foreach_vcdp_sp_node
#undef _
}

clib_error_t *
vcdp_tenant_add_del (vcdp_main_t *vcdp, u32 tenant_id, u32 context_id,
		     u8 is_del)
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
	  tenant->bitmaps[VCDP_FLOW_REVERSE] = VCDP_DEFAULT_BITMAP;
	  tenant->tenant_id = tenant_id;
	  tenant->context_id = context_id;
	  vcdp_tenant_init_timeouts (tenant);
	  vcdp_tenant_init_sp_nodes (tenant);
	  kv.key = tenant_id;
	  kv.value = tenant_idx;
	  clib_bihash_add_del_8_8 (&vcdp->tenant_idx_by_id, &kv, 1);
	  vcdp_tenant_clear_counters (vcdp, tenant_idx);
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
	  vcdp_tenant_clear_counters (vcdp, kv.value);
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

clib_error_t *
vcdp_set_timeout (vcdp_main_t *vcdp, u32 tenant_id, u32 timeout_idx,
		  u32 timeout_val)
{
  vcdp_init_main_if_needed (vcdp);
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  vcdp_tenant_t *tenant;
  if (clib_bihash_search_inline_8_8 (&vcdp->tenant_idx_by_id, &kv))
    return clib_error_return (
      0, "Can't configure timeout: tenant id %d not found", tenant_id);
  tenant = vcdp_tenant_at_index (vcdp, kv.value);
  tenant->timeouts[timeout_idx] = timeout_val;
  return 0;
}

clib_error_t *
vcdp_set_sp_node (vcdp_main_t *vcdp, u32 tenant_id, u32 sp_index,
		  u32 node_index)
{
  vcdp_init_main_if_needed (vcdp);
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  vcdp_tenant_t *tenant;
  if (clib_bihash_search_inline_8_8 (&vcdp->tenant_idx_by_id, &kv))
    return clib_error_return (
      0, "Can't configure slow path node: tenant id %d not found", tenant_id);
  tenant = vcdp_tenant_at_index (vcdp, kv.value);
  tenant->sp_node_indices[sp_index] = node_index;
  return 0;
}

void
vcdp_normalise_ip4_key (vcdp_session_t *session,
			vcdp_session_ip4_key_t *result, u8 key_idx)
{
  vcdp_session_ip4_key_t *skey = &session->keys[key_idx].key4;
  vcdp_ip4_key_t *key = &skey->ip4_key;
  u8 pseudo_dir = session->pseudo_dir[key_idx];
  u8 proto = session->proto;
  u8 with_port = proto == IP_PROTOCOL_UDP || proto == IP_PROTOCOL_TCP ||
		 proto == IP_PROTOCOL_ICMP;

  result->ip4_key.as_u64x2 = key->as_u64x2;
  result->as_u64 = skey->as_u64;
  if (with_port && pseudo_dir)
    {
      result->ip4_key.ip_addr_lo = key->ip_addr_hi;
      result->ip4_key.port_lo = clib_net_to_host_u16 (key->port_hi);
      result->ip4_key.ip_addr_hi = key->ip_addr_lo;
      result->ip4_key.port_hi = clib_net_to_host_u16 (key->port_lo);
    }
  else
    {
      result->ip4_key.ip_addr_lo = key->ip_addr_lo;
      result->ip4_key.port_lo = clib_net_to_host_u16 (key->port_lo);
      result->ip4_key.ip_addr_hi = key->ip_addr_hi;
      result->ip4_key.port_hi = clib_net_to_host_u16 (key->port_hi);
    }
}

void
vcdp_normalise_ip6_key (vcdp_session_t *session,
			vcdp_session_ip6_key_t *result, u8 key_idx)
{
  vcdp_session_ip6_key_t *skey = &session->keys[key_idx].key6;
  vcdp_ip6_key_t *key = &skey->ip6_key;
  u8 pseudo_dir = session->pseudo_dir[key_idx];
  u8 proto = session->proto;
  u8 with_port = proto == IP_PROTOCOL_UDP || proto == IP_PROTOCOL_TCP ||
		 proto == IP_PROTOCOL_ICMP;

  result->ip6_key.as_u64x4 = key->as_u64x4;
  result->as_u64 = skey->as_u64;
  if (with_port && pseudo_dir)
    {
      result->ip6_key.ip6_addr_lo = key->ip6_addr_hi;
      result->ip6_key.port_lo = clib_net_to_host_u16 (key->port_hi);
      result->ip6_key.ip6_addr_hi = key->ip6_addr_lo;
      result->ip6_key.port_hi = clib_net_to_host_u16 (key->port_lo);
    }
  else
    {
      result->ip6_key.ip6_addr_lo = key->ip6_addr_lo;
      result->ip6_key.port_lo = clib_net_to_host_u16 (key->port_lo);
      result->ip6_key.ip6_addr_hi = key->ip6_addr_hi;
      result->ip6_key.port_hi = clib_net_to_host_u16 (key->port_hi);
    }
}

int
vcdp_bihash_add_del_inline_with_hash_24_8 (clib_bihash_24_8_t *h,
					   clib_bihash_kv_24_8_t *kv, u64 hash,
					   u8 is_add)
{
  return clib_bihash_add_del_inline_with_hash_24_8 (h, kv, hash, is_add, 0, 0,
						    0, 0);
}

int
vcdp_bihash_add_del_inline_with_hash_48_8 (clib_bihash_48_8_t *h,
					   clib_bihash_kv_48_8_t *kv, u64 hash,
					   u8 is_add)
{
  return clib_bihash_add_del_inline_with_hash_48_8 (h, kv, hash, is_add, 0, 0,
						    0, 0);
}

VLIB_INIT_FUNCTION (vcdp_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VCDP_CORE_PLUGIN_BUILD_VER,
  .description = "vCDP Core Plugin",
};
