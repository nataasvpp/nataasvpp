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
#include <vppinfra/bihash_template.h>

#define GW_LOG2_FLOWS_PER_THREAD 26

#define BIHASH_IP4_NUM_BUCKETS (1 << (GW_LOG2_FLOWS_PER_THREAD - 2))
#define BIHASH_IP4_MEM_SIZE    (2ULL << 30)

#define GW_FLOW_ID_DIRECTION_SHIFT (31)
#define GW_FLOW_ID_DIRECTION_MASK  (1 << GW_FLOW_ID_DIRECTION_SHIFT)
#define GW_FLOW_ID_TYPE_SHIFT	   (29)
#define GW_FLOW_ID_TYPE_MASK	   (3 << GW_FLOW_ID_TYPE_SHIFT)

typedef union
{
  struct
  {
    union
    {
      u32 spi;
      struct
      {
	u16 port_lo;
	u16 port_hi;
      };
      struct
      {
	u8 type;
	u8 code;
      };
    };
    u8 unused;
    u8 proto;
    u16 unused2;
    u32 ip_addr_lo;
    u32 ip_addr_hi;
  };
  u8x16 as_u8x16;
  u32x4 as_u32x4;
  u64x2 as_u64x2;
} __clib_packed gw_ip4_key_t;

STATIC_ASSERT_SIZEOF (gw_ip4_key_t, 16);

typedef struct
{
  u32 ip_addr_hi;
  u32 ip_addr_lo;
  u16 port_hi;
  u16 port_lo;
  u8 proto;
} gw_flow_t;

STATIC_ASSERT_SIZEOF (gw_flow_t, 16);

typedef struct
{
  gw_flow_t *flows;
} gw_per_thread_data_t;

typedef struct
{
  u32 tenant_id;
} gw_tenant_t;

typedef struct
{
  u32 *next_index_by_rx_sw_if_index;
  u32 *tx_sw_if_index_by_rx_sw_if_index;
  clib_bihash_24_8_t table4;
  u32 frame_queue_index;

  /* pool of tenants */
  gw_tenant_t *tenants;

  /* per-thread data */
  gw_per_thread_data_t *per_thread_data;

} gw_main_t;

extern gw_main_t gateway_main;

extern vlib_node_registration_t gw_lookup_node;
extern vlib_node_registration_t gw_counter_node;
extern vlib_node_registration_t gw_exporter_node;

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u64 hash;
  u32 flow_id;
} gw_lookup_trace_t;

format_function_t format_gw_flow;
format_function_t format_gw_flow_with_dir;

typedef enum
{
  GW_FLOW_TYPE_IP4,
  GW_FLOW_TYPE_IP6,
  /* last */
  GW_FLOW_N_TYPES,
} gw_flow_type_t;

static_always_inline u32
gw_flow_id (gw_flow_type_t type, u32 thread_index, u32 local_index,
	    u32 direction)
{
  u32 flow_id;
  ASSERT (type < GW_FLOW_N_TYPES);
  ASSERT (local_index < (1 << GW_LOG2_FLOWS_PER_THREAD));

  flow_id = local_index;
  flow_id |= thread_index << GW_LOG2_FLOWS_PER_THREAD;
  flow_id |= type << 29;
  flow_id |= direction << 31;
  return flow_id;
}

static_always_inline u32
gw_thread_index_from_flow_id (u32 flow_id)
{
  flow_id &= ~(GW_FLOW_ID_DIRECTION_MASK | GW_FLOW_ID_TYPE_MASK);
  return flow_id >> GW_LOG2_FLOWS_PER_THREAD;
}

static_always_inline u32
gw_local_index_from_flow_id (u32 flow_id)
{
  return flow_id & pow2_mask (GW_LOG2_FLOWS_PER_THREAD);
}

static_always_inline u8
gw_direction_from_flow_id (u32 flow_id)
{
  return flow_id >> GW_FLOW_ID_DIRECTION_SHIFT;
}

static_always_inline gw_flow_t *
gw_get_flow (u32 flow_id)
{
  gw_main_t *fm = &gateway_main;
  u32 thread_index = gw_thread_index_from_flow_id (flow_id);
  gw_per_thread_data_t *ptd =
    vec_elt_at_index (fm->per_thread_data, thread_index);
  return pool_elt_at_index (ptd->flows, gw_local_index_from_flow_id (flow_id));
}

int gateway_enable_disable (gw_main_t *gm, u32 sw_if_index1, u32 sw_if_index2,
			    int enable_disable);

#define VCDP_GW_PLUGIN_BUILD_VER "1.0"

#endif /* __included_gateway_h__ */
