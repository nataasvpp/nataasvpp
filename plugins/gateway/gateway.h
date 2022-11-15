// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_gateway_h
#define included_gateway_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vcdp/vcdp.h>

#define foreach_gw_tenant_flag                                                                                         \
  _(OUTPUT_DATA_SET, "output-data-set", 0)                                                                             \
  _(STATIC_MAC, "static-mac", 1)

typedef enum {
#define _(a, b, c) GW_TENANT_F_##a = (1 << (c)),
  foreach_gw_tenant_flag
#undef _
} gw_tenant_flags_t;
typedef struct {
  u32 flags;
} gw_tenant_t;

typedef struct {
  /* pool of tenants */
  gw_tenant_t *tenants;

  u16 msg_id_base;

  u16 *tenant_idx_by_sw_if_idx; /* vec */
} gw_main_t;

extern gw_main_t gateway_main;

static_always_inline gw_tenant_t *
gw_tenant_at_index(gw_main_t *gm, u32 idx)
{
  return vec_elt_at_index(gm->tenants, idx);
}

int gw_interface_input_enable(u32 sw_if_index, u32 tenant_id);

#endif /* included_gateway_h */
