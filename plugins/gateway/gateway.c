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
gateway_init_main_if_needed(gw_main_t *gm) {
  static u32 done = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main();
  if (done)
    return;

  /* initialize per-thread pools */
  vec_validate(gm->per_thread_data, tm->n_vlib_mains - 1);
  for (int i = 0; i < tm->n_vlib_mains; i++) {
    gw_per_thread_data_t *ptd = vec_elt_at_index(gm->per_thread_data, i);
    vec_validate(ptd->output, 1ULL << (VCDP_LOG2_SESSIONS_PER_THREAD + 1));
  }
  vec_validate(gm->tenants, 1ULL << VCDP_LOG2_TENANTS);

  done = 1;
}

static clib_error_t *
gateway_init(vlib_main_t *vm) {
  return 0;
}

void
gw_enable_disable_geneve_input(gw_enable_disable_geneve_input_args_t *args) {
  gw_main_t *gm = &gateway_main;
  int rv = 0;
  gateway_init_main_if_needed(gm);
  rv =
    vnet_feature_enable_disable("ip4-unicast", "vcdp-geneve-input",
                                args->sw_if_index, args->enable_disable, 0, 0);
  args->rv = rv;
  if (rv)
    args->err = clib_error_return(
      0, "Failed vnet_feature_enable_disable with error %d : %U", rv,
      format_vnet_api_errno, rv);
  else
    args->err = 0;
}

void
gw_set_geneve_output(gw_set_geneve_output_args_t *args) {
  gw_main_t *gm = &gateway_main;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tenant_t *vt;
  gw_tenant_t *gt;
  clib_bihash_kv_8_8_t kv = {};
  u8 dir = !!args->direction;
  kv.key = args->tenant_id;
  if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv)) {
    args->rv = -1;
    args->err = clib_error_return(0, "tenant-id %d not found", args->tenant_id);
    return;
  }
  vt = vcdp_tenant_at_index(vcdp, kv.value);
  gt = gw_tenant_at_index(gm, kv.value);

  /* Caching tenant id in gt */
  gt->output_tenant_id =
    args->output_tenant_id == ~0 ? vt->tenant_id : args->output_tenant_id;
  gt->flags = GW_TENANT_F_OUTPUT_DATA_SET;
  gt->geneve_src_ip[dir] = args->src_addr;
  gt->geneve_dst_ip[dir] = args->dst_addr;
  gt->geneve_src_port[dir] = args->src_port;
  gt->geneve_dst_port[dir] = args->dst_port;
  if (args->static_mac) {
    gt->flags |= GW_TENANT_F_STATIC_MAC;
    gt->src_mac[dir] = args->src_mac;
    gt->dst_mac[dir] = args->dst_mac;
  }
  args->rv = 0;
  args->err = 0;
}

VLIB_INIT_FUNCTION(gateway_init);
VLIB_PLUGIN_REGISTER() = {
  .version = VCDP_GW_PLUGIN_BUILD_VER,
  .description = "vCDP Gateway Plugin",
};