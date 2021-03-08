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

#define GW_LOG2_SESSIONS_PER_THREAD 26

#define BIHASH_IP4_NUM_BUCKETS (1 << (GW_LOG2_SESSIONS_PER_THREAD - 2))
#define BIHASH_IP4_MEM_SIZE    (2ULL << 30)

#define BIHASH_IP6_NUM_BUCKETS (1 << (GW_LOG2_SESSIONS_PER_THREAD - 2))
#define BIHASH_IP6_MEM_SIZE    (2ULL << 30)

/* Convention session_index is 31 bit
 * Flow_index (embedded in vlib_buffer_t as "flow_id")
 * Flow_index = (session_index << 1) + !(is_forward)

 * A flow is "forward" if it's going from initiator to responder
 * The packet_direction is 1 if normalisation happened 0 otherwise
 * the stored_direction of a flow is the packet direction of its FSOL
 * Pseudo_flow_index = (session_index << 1) + stored_direction
 *
 * Note that for a packet belonging to a flow
 * ----------------------------------------------------------
 *     !(is_forward) = packet_direction ^ stored_direction
 *        Flow_index = Pseudo_flow_index ^ stored_direction
 * ----------------------------------------------------------
 */

typedef enum
{
  GW_SESSION_TYPE_IP4,

  /* last */
  GW_SESSION_N_TYPES,
} gw_session_type_t;

enum
{
  GW_FLOW_FORWARD = 0,
  GW_FLOW_BACKWARD = 1,
  GW_FLOW_F_B_N = 2
};

enum
{
  GW_PACKET_ORIGINAL = 0,
  GW_PACKET_NORMALISED = 1
};

typedef struct
{
  u32 bitmaps[GW_FLOW_F_B_N];
  u8 type; /* see gw_session_type_t */

  /* Deprecated fields: */
  u32 ip_addr_hi;
  u32 ip_addr_lo;
  u16 port_hi;
  u16 port_lo;
  u8 proto;
} gw_session_t;

typedef struct
{

} gw_geneve_output_data_t;

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
  gw_ip4_key_t ip4_key;

  union
  {
    struct
    {
      u32 tenant_id;
      u8 zeros[4];
    };
    u64 as_u64;
  };
} __clib_packed gw_session_ip4_key_t;
STATIC_ASSERT_SIZEOF (gw_session_ip4_key_t, 24);

typedef struct
{
  /* Infra data */
  gw_session_t *sessions; /* fixed pool */

  /* Service nodes data */

  /* geneve-input specific data */

  /* geneve-output specific data */
  gw_geneve_output_data_t *output; /* by flow_index */
} gw_per_thread_data_t;

typedef struct
{
  u32 tenant_id;
} gw_tenant_t;

typedef struct
{
  u32 *next_index_by_rx_sw_if_index;
  u32 *tx_sw_if_index_by_rx_sw_if_index;

  /* key = (u64) tenant_id; val= (u64) tenant_idx; */
  clib_bihash_8_8_t tenant_idx_by_id;

  /* (gw_session_ip4_key_t) -> (thread_index(32 MSB),session_index(31 bits),
   * stored_direction (1 LSB)) */
  clib_bihash_24_8_t table4;
  u32 frame_queue_index;

  /* pool of tenants */
  gw_tenant_t *tenants;

  /* per-thread data */
  gw_per_thread_data_t *per_thread_data;

} gw_main_t;

extern gw_main_t gateway_main;
extern vlib_node_registration_t gw_lookup_node;
extern vlib_node_registration_t gw_handoff_node;
extern vlib_node_registration_t gw_counter_node;
extern vlib_node_registration_t gw_exporter_node;

format_function_t format_gw_session;

static_always_inline u32
gw_session_index_from_lookup (u64 val)
{
  return (val >> 1) & (~(u32) 0);
}

static_always_inline u32
gw_thread_index_from_lookup (u64 val)
{
  return val >> 32;
}

static_always_inline u32
gw_packet_dir_from_lookup (u64 val)
{
  return val & 0x1;
}

static_always_inline u32
gw_pseudo_flow_index_from_lookup (u64 val)
{
  return val & (~(u32) 0);
}

static_always_inline u64
gw_session_mk_table_value (u32 thread_index, u32 pseudo_flow_index)
{
  return ((u64) thread_index << 32) | pseudo_flow_index;
}

static_always_inline gw_session_t *
gw_session_at_index (gw_per_thread_data_t *ptd, u32 idx)
{
  return pool_elt_at_index (ptd->sessions, idx);
}

static_always_inline u32
gw_mk_flow_index (u32 session_index, u8 dir)
{
  return (session_index << 1) | !(dir == GW_FLOW_FORWARD);
}

static_always_inline u32
gw_session_from_flow_index (u32 flow_index)
{
  return flow_index >> 1;
}

static_always_inline u32
gw_direction_from_flow_index (u32 flow_index)
{
  return (flow_index & 0x1);
}
/* static_always_inline u32
gw_flow_id (gw_flow_type_t type, u32 thread_index, u32 local_index,
	    u32 direction)
{
  u32 flow_id;
  ASSERT (type < GW_SESSION_N_TYPES);
  ASSERT (local_index < (1 << GW_LOG2_SESSIONS_PER_THREAD));

  flow_id = local_index;
  flow_id |= thread_index << GW_LOG2_SESSIONS_PER_THREAD;
  flow_id |= type << 29;
  flow_id |= direction << 31;
  return flow_id;
}

static_always_inline u32
gw_thread_index_from_flow_id (u32 flow_id)
{
  flow_id &= ~(GW_FLOW_ID_DIRECTION_MASK | GW_FLOW_ID_TYPE_MASK);
  return flow_id >> GW_LOG2_SESSIONS_PER_THREAD;
}

static_always_inline u32
gw_local_index_from_flow_id (u32 flow_id)
{
  return flow_id & pow2_mask (GW_LOG2_SESSIONS_PER_THREAD);
}

static_always_inline u8
gw_direction_from_flow_id (u32 flow_id)
{
  return flow_id >> GW_FLOW_ID_DIRECTION_SHIFT;
}

static_always_inline gw_session_t *
gw_get_session (u32 flow_id)
{
  gw_main_t *fm = &gateway_main;
  u32 thread_index = gw_thread_index_from_flow_id (flow_id);
  gw_per_thread_data_t *ptd =
    vec_elt_at_index (fm->per_thread_data, thread_index);
  return pool_elt_at_index (ptd->flows, gw_local_index_from_flow_id (flow_id));
} */

int gateway_enable_disable (gw_main_t *gm, u32 sw_if_index1, u32 sw_if_index2,
			    int enable_disable);

#define VCDP_GW_PLUGIN_BUILD_VER "1.0"

#endif /* __included_gateway_h__ */
