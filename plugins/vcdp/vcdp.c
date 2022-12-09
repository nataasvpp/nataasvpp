// Copyright(c) 2022 Cisco Systems, Inc.

#define _GNU_SOURCE
#include <sys/mman.h>

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.c>

#include <vcdp/vcdp.h>
#include <vcdp/lookup/lookup_inlines.h>
#include <vcdp/service.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>

#define VCDP_DEFAULT_BITMAP VCDP_SERVICE_MASK(drop)

VCDP_SERVICE_DECLARE(drop)

vcdp_main_t vcdp_main;
vcdp_cfg_main_t vcdp_cfg_main;

static void
vcdp_timer_expired(u32 *expired)
{
  u32 *e;
  uword thread_index = vlib_get_thread_index();
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vec_foreach (e, expired) {
    u32 session_idx = e[0] & VCDP_TIMER_SI_MASK;
    vec_add1(ptd->expired_sessions, session_idx);
  }
}

static void
vcdp_init_tenant_counters(vcdp_main_t *vcdp, u32 no_tenants)
{
#define _(x, y, z)                                                                                                     \
  vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x].name = y;                                                  \
  vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x].stat_segment_name = "/vcdp/per_tenant_counters/" y;        \
  vlib_validate_simple_counter(&vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x], no_tenants);                           \

  foreach_vcdp_tenant_session_counter
#undef _
#define _(x, y, z)                                                                                                     \
  vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x].name = y;                                                        \
  vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x].stat_segment_name = "/vcdp/per_tenant_counters/" y;              \
  vlib_validate_combined_counter(&vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x], no_tenants);

    foreach_vcdp_tenant_data_counter
#undef _
}

vcdp_cfg_main_t vcdp_cfg_main;

static clib_error_t *
vcdp_init(vlib_main_t *vm)
{
  vcdp_main_t *vcdp = &vcdp_main;

  vlib_call_init_function(vm, vcdp_service_init);
  vcdp_service_next_indices_init(vm, vcdp_lookup_ip4_node.index);
  vcdp_service_next_indices_init(vm, vcdp_handoff_node.index);

  vlib_thread_main_t *tm = vlib_get_thread_main();
  time_t epoch = time(NULL);
  uword log_n_thread = max_log2(tm->n_vlib_mains);
  uword template_shift = VCDP_SESSION_ID_TOTAL_BITS - VCDP_SESSION_ID_EPOCH_N_BITS - log_n_thread;
  vcdp->session_id_ctr_mask = (((u64) 1 << template_shift) - 1);
  /* initialize per-thread data */
  vec_validate(vcdp->per_thread_data, tm->n_vlib_mains - 1);
  for (int i = 0; i < tm->n_vlib_mains; i++) {
    vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, i);
    pool_init_fixed(ptd->sessions, vcdp_cfg_main.no_sessions_per_thread);
    vcdp_tw_init(&ptd->wheel, vcdp_timer_expired, VCDP_TIMER_INTERVAL, ~0);
    ptd->session_id_template = (u64) epoch << (template_shift + log_n_thread);
    ptd->session_id_template |= (u64) i << template_shift;
  }
  pool_init_fixed(vcdp->tenants, vcdp_cfg_main.no_tenants);
  vcdp_init_tenant_counters(vcdp, vcdp_cfg_main.no_tenants);

  u32 session_buckets = vcdp_calc_bihash_buckets(vcdp_cfg_main.no_sessions_per_thread);
  u32 tenant_buckets = vcdp_calc_bihash_buckets(vcdp_cfg_main.no_tenants);

  clib_bihash_init_16_8(&vcdp->table4, "vcdp ipv4 session table", session_buckets, 0);
  clib_bihash_init_8_8(&vcdp->tenant_idx_by_id, "vcdp tenant table", tenant_buckets, 0);
  clib_bihash_init_8_8(&vcdp->session_index_by_id, "session idx by id", session_buckets, 0);

  vcdp->frame_queue_index = vlib_frame_queue_main_init (vcdp_handoff_node.index, 0);

  return 0;
}

static void
vcdp_enable_disable_timer_expire_node(u8 is_enable)
{
  vlib_main_t *vm;
  u32 n_vms = vlib_num_workers() + 1;
  /* Maybe disable main thread if workers are present */
  for (int i = 0; i < n_vms; i++) {
    vm = vlib_get_main_by_index(i);
    vlib_node_t *node = vlib_get_node_by_name(vm, (u8 *) "vcdp-timer-expire");
    vlib_node_set_state(vm, node->index, is_enable ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED);
  }
}

void
vcdp_tenant_clear_counters(vcdp_main_t *vcdp, u32 tenant_idx)
{
#define _(x, y, z)                                                                                                     \
  vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x].name = y;                                                  \
  vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x].stat_segment_name = "/vcdp/per_tenant_counters/" y;        \
  vlib_zero_simple_counter(&vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x], tenant_idx);

  foreach_vcdp_tenant_session_counter
#undef _
#define _(x, y, z)                                                                                                     \
  vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x].name = y;                                                        \
  vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x].stat_segment_name = "/vcdp/per_tenant_counters/" y;              \
  vlib_zero_combined_counter(&vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x], tenant_idx);

    foreach_vcdp_tenant_data_counter
#undef _
}

static void
vcdp_tenant_init_timeouts(vcdp_tenant_t *tenant)
{
#define _(x, y, z) tenant->timeouts[VCDP_TIMEOUT_##x] = y;
  foreach_vcdp_timeout
#undef _
}

clib_error_t *
vcdp_tenant_add_del(vcdp_main_t *vcdp, u32 tenant_id, u32 context_id, vcdp_tenant_flags_t flags, u8 is_add)
{
  clib_bihash_kv_8_8_t kv = {.key = tenant_id, .value = 0};
  clib_error_t *err = 0;
  vcdp_tenant_t *tenant;
  u32 tenant_idx;
  u32 n_tenants = pool_elts(vcdp->tenants);
  if (is_add) {
    if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv)) {
      pool_get(vcdp->tenants, tenant);
      tenant_idx = tenant - vcdp->tenants;
      tenant->bitmaps[VCDP_FLOW_FORWARD] = VCDP_DEFAULT_BITMAP;
      tenant->bitmaps[VCDP_FLOW_REVERSE] = VCDP_DEFAULT_BITMAP;
      tenant->tenant_id = tenant_id;
      tenant->context_id = context_id;
      tenant->flags = flags;
      vcdp_tenant_init_timeouts(tenant);
      kv.key = tenant_id;
      kv.value = tenant_idx;
      clib_bihash_add_del_8_8(&vcdp->tenant_idx_by_id, &kv, 1);
      vcdp_tenant_clear_counters(vcdp, tenant_idx);
      if (n_tenants == 0)
        vcdp_enable_disable_timer_expire_node(is_add);

    } else {
      err = clib_error_return(0,
                              "Can't create tenant with id %d"
                              " (already exists with index %d)",
                              tenant_id, kv.value);
    }
  } else {
    if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv)) {
      err = clib_error_return(0,
                              "Can't delete tenant with id %d"
                              " (not found)",
                              tenant_id);
    } else {
      vcdp_tenant_clear_counters(vcdp, kv.value);
      pool_put_index(vcdp->tenants, kv.value);
      clib_bihash_add_del_8_8(&vcdp->tenant_idx_by_id, &kv, 0);
      /* TODO: Notify other users of "tenants" (like gw)?
       * maybe cb list? */
    }
  }
#if 0
  // Disable timer expiry if last tenant has gone?
  if (!err && ((n_tenants == 1 && !is_add) || (n_tenants == 0 && is_add)))
    vcdp_enable_disable_timer_expire_node(is_add);
#endif
  return err;
}

clib_error_t *
vcdp_set_services(vcdp_main_t *vcdp, u32 tenant_id, u32 bitmap, vcdp_session_direction_t direction)
{
  clib_bihash_kv_8_8_t kv = {.key = tenant_id, .value = 0};
  vcdp_tenant_t *tenant;
  if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv))
    return clib_error_return(0, "Can't assign service map: tenant id %d not found", tenant_id);

  tenant = vcdp_tenant_at_index(vcdp, kv.value);
  tenant->bitmaps[direction] = bitmap;
  return 0;
}

clib_error_t *
vcdp_set_timeout(vcdp_main_t *vcdp, u32 tenant_id, u32 timeout_idx, u32 timeout_val)
{
  clib_bihash_kv_8_8_t kv = {.key = tenant_id, .value = 0};
  vcdp_tenant_t *tenant;
  if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv))
    return clib_error_return(0, "Can't configure timeout: tenant id %d not found", tenant_id);
  tenant = vcdp_tenant_at_index(vcdp, kv.value);
  tenant->timeouts[timeout_idx] = timeout_val;
  return 0;
}

int
vcdp_bihash_add_del_inline_with_hash_16_8(clib_bihash_16_8_t *h, clib_bihash_kv_16_8_t *kv, u64 hash, u8 is_add)
{
  return clib_bihash_add_del_inline_with_hash_16_8(h, kv, hash, is_add, 0, 0, 0, 0);
}

// TODO: Change to sparse vector or something more lightweight than bihash
u16
vcdp_tenant_idx_by_id(u32 tenant_id) {
  vcdp_main_t *vcdp = &vcdp_main;
  clib_bihash_kv_8_8_t kv = {.key = tenant_id};

  if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv)) {
    /* Not found */
    return ~0;
  }
  return kv.value;
}

vcdp_tenant_t *
vcdp_tenant_get_by_id(u32 tenant_id, u16 *tenant_idx)
{
  vcdp_main_t *vcdp = &vcdp_main;

  *tenant_idx = vcdp_tenant_idx_by_id(tenant_id);

  clib_bihash_kv_8_8_t kv = {.key = tenant_id};

  if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv)) {
    /* Not found */
    return 0;
  }
  *tenant_idx = kv.value;
  return vcdp_tenant_at_index(&vcdp_main, *tenant_idx);
}

VLIB_INIT_FUNCTION(vcdp_init);

VLIB_PLUGIN_REGISTER() = {
  .version = VCDP_CORE_PLUGIN_BUILD_VER,
  .description = "vCDP Core Plugin",
};

static clib_error_t *
vcdp_config(vlib_main_t *vm, unformat_input_t *input)
{
  u32 tenants = 0;
  u32 tunnels = 0;
  u32 nat_instances = 0;
  u32 sessions = 0;

  /* Set defaults */
  vcdp_cfg_main.no_nat_instances = 1 << 10; // 1024
  vcdp_cfg_main.no_sessions_per_thread = 1 << 20; // 1M
  vcdp_cfg_main.no_tenants = 1 << 10; // 1024
  vcdp_cfg_main.no_tunnels = 1 << 20; // 1M;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "tenants %d", &tenants))
      vcdp_cfg_main.no_tenants = tenants;
    else if (unformat(input, "tunnels %d", &tunnels))
      vcdp_cfg_main.no_tunnels = tunnels;
    else if (unformat(input, "nat-instances %d", &nat_instances))
      vcdp_cfg_main.no_nat_instances = nat_instances;
    else if (unformat(input, "sessions-per-thread %d", &sessions))
      vcdp_cfg_main.no_sessions_per_thread = sessions;
    else
      return clib_error_return(0, "unknown input '%U'", format_unformat_error, input);
  }
  return 0;
}
VLIB_EARLY_CONFIG_FUNCTION(vcdp_config, "vcdp");
