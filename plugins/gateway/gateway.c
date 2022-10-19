// Copyright(c) 2022 Cisco Systems, Inc.

#define _GNU_SOURCE
#include <sys/mman.h>

#include <gateway/gateway.h>

#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

gw_main_t gateway_main;

__clib_unused static void
gateway_init_main_if_needed(gw_main_t *gm)
{
  static u32 done = 0;
  // vlib_thread_main_t *tm = vlib_get_thread_main();
  if (done)
    return;

  /* initialize per-thread pools */
  // vec_validate(gm->per_thread_data, tm->n_vlib_mains - 1);
  // for (int i = 0; i < tm->n_vlib_mains; i++) {
  //   gw_per_thread_data_t *ptd = vec_elt_at_index(gm->per_thread_data, i);
  //   vec_validate(ptd->output, 1ULL << (VCDP_LOG2_SESSIONS_PER_THREAD + 1));
  // }
  vec_validate(gm->tenants, 1ULL << VCDP_LOG2_TENANTS);

  done = 1;
}

static clib_error_t *
gateway_init(vlib_main_t *vm)
{
  return 0;
}

int
gw_interface_input_enable(u32 sw_if_index, u32 tenant_id)
{
  gw_main_t *gm = &gateway_main;
  gateway_init_main_if_needed(gm);
  u16 *config;
  u16 tenant_idx;

  vcdp_tenant_t *tenant = vcdp_tenant_get_by_id(tenant_id, &tenant_idx);
  if (!tenant)
    return -1;

  vec_validate(gm->tenants, tenant_idx);
  vec_validate(gm->tenant_idx_by_sw_if_idx, sw_if_index);
  config = gm->tenant_idx_by_sw_if_idx + sw_if_index;
  config[0] = tenant_idx;

  return vnet_feature_enable_disable("ip4-unicast", "vcdp-input", sw_if_index, 1, 0, 0);
}

VLIB_INIT_FUNCTION(gateway_init);
VLIB_PLUGIN_REGISTER() = {
  .version = VCDP_GW_PLUGIN_BUILD_VER,
  .description = "vCDP Gateway Plugin",
};
