// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#define _GNU_SOURCE
#include <sys/mman.h>

#include <gateway/gateway.h>
#include <vnet/vnet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

gw_main_t gateway_main;

int
gw_interface_input_enable_disable(u32 sw_if_index, u32 tenant_id, bool is_enable)
{
  gw_main_t *gm = &gateway_main;
  u16 *config;
  u16 tenant_idx;

  if (is_enable) {
    vcdp_tenant_t *tenant = vcdp_tenant_get_by_id(tenant_id, &tenant_idx);
    if (!tenant)
      return -1;

    vec_validate(gm->tenant_idx_by_sw_if_idx, sw_if_index);
    config = gm->tenant_idx_by_sw_if_idx + sw_if_index;
    config[0] = tenant_idx;
  }
  return vnet_feature_enable_disable("ip4-unicast", "vcdp-input", sw_if_index, is_enable, 0, 0);
}
