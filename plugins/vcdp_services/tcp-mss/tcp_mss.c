// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp/vcdp.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include "tcp_mss.h"

vcdp_tcp_mss_main_t vcdp_tcp_mss_main;

int
vcdp_tcp_mss_enable_disable(u32 tenant_id, u16 mss4_forward, u16 mss4_reverse, bool is_enable)
{
  vcdp_tcp_mss_main_t *cm = &vcdp_tcp_mss_main;
  u16 tenant_idx;

  vcdp_tenant_t *tenant = vcdp_tenant_get_by_id(tenant_id, &tenant_idx);
  if (!tenant) return -1;
  int rv = 0;
  if (!is_enable) {
    mss4_forward = MSS_CLAMP_UNSET;
    mss4_reverse = MSS_CLAMP_UNSET;
  }
  vec_validate_init_empty(cm->max_mss4_forward, tenant_idx, MSS_CLAMP_UNSET);
  cm->max_mss4_forward[tenant_idx] = mss4_forward;
  vec_validate_init_empty(cm->max_mss4_reverse, tenant_idx, MSS_CLAMP_UNSET);
  cm->max_mss4_reverse[tenant_idx] = mss4_reverse;

  return rv;
}
