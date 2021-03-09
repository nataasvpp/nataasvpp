/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_gateway_h__
#define __included_gateway_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_8_8.h>

#include <vppinfra/bihash_template.h>

#include <vcdp/vcdp.h>

typedef struct
{
  /* Here goes the geneve rewrite */
} gw_geneve_output_data_t;

typedef struct
{
  gw_geneve_output_data_t *output; /* by flow_index */
} gw_per_thread_data_t;

typedef struct
{
  u32 tenant_id;

  /* Geneve output spec for forward/backwards packets */
  ip4_address_t geneve_src_ip[VCDP_FLOW_F_B_N];
  ip4_address_t geneve_dst_ip[VCDP_FLOW_F_B_N];
  u16 geneve_src_port[VCDP_FLOW_F_B_N];
  u16 geneve_dst_port[VCDP_FLOW_F_B_N];

} gw_tenant_t;

typedef struct
{
  /* pool of tenants */
  gw_tenant_t *tenants;

  /* per-thread data */
  gw_per_thread_data_t *per_thread_data;
} gw_main_t;

extern gw_main_t gateway_main;

static_always_inline gw_tenant_t *
gw_tenant_at_index (gw_main_t *gm, u32 idx)
{
  return pool_elt_at_index (gm->tenants, idx);
}

#endif /* __included_gateway_h__ */
