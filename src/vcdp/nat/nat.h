/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#ifndef __included_nat_h__
#define __included_nat_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip46_address.h>

#define NAT_INVALID_TENANT_IDX	(u16) (~0)
#define NAT_ALLOC_POOL_ARRAY_SZ 13

#define foreach_nat_tenant_flag _ (SNAT, 0x1, "snat")

enum
{
#define _(name, x, str) NAT_TENANT_FLAG_##name = (x),
  foreach_nat_tenant_flag
#undef _
    NAT_TENANT_N_FLAGS
};

typedef struct
{
  u16 flags;
  uword out_alloc_pool_idx;
  uword fib_index;
} nat_tenant_t;

typedef struct
{

} nat_rewrite_data_t;

typedef struct
{
  nat_rewrite_data_t *flows; /* by flow_index */
} nat_per_thread_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cache0);
  u16 flags;
  u16 num;
  ip4_address_t addr[NAT_ALLOC_POOL_ARRAY_SZ];
  ip4_address_t *remaining;
} nat_alloc_pool_t;
STATIC_ASSERT_SIZEOF (nat_alloc_pool_t, CLIB_CACHE_LINE_BYTES);

typedef struct
{
  u16 *tenant_idx_by_sw_if_idx; /* vec */
  nat_tenant_t *tenants;	/* vec */
  nat_alloc_pool_t *alloc_pool; /* pool of allocation pools */
  nat_per_thread_data_t *ptd;	/* vec */
  uword *alloc_pool_idx_by_id;	/* hash */
} nat_main_t;

extern nat_main_t nat_main;

clib_error_t *nat_external_interface_set_tenant (nat_main_t *nat,
						 u32 sw_if_index,
						 u32 tenant_id, u8 unset);

clib_error_t *nat_alloc_pool_add_del (nat_main_t *nat, u32 alloc_pool_id,
				      u8 is_del, ip4_address_t *addr,
				      uword fib_index);

clib_error_t *nat_tenant_set_snat (nat_main_t *nat, u32 tenant_id,
				   u32 table_id, u32 alloc_pool_id, u8 unset);

#endif