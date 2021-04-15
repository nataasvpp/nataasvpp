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
#ifndef __included_vcdp_h__
#define __included_vcdp_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_8_8.h>

#include <vppinfra/bihash_template.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#include <vcdp/timer/timer.h>

#define VCDP_LOG2_SESSIONS_PER_THREAD 19
#define VCDP_LOG2_TENANTS	      10
#define VCDP_SESSION_ID_TOTAL_BITS    64
#define VCDP_SESSION_ID_EPOCH_N_BITS  16
#define BIHASH_IP4_NUM_BUCKETS	      (1 << (VCDP_LOG2_SESSIONS_PER_THREAD - 2))
#define BIHASH_IP4_MEM_SIZE	      (2ULL << 30)

#define BIHASH_IP6_NUM_BUCKETS (1 << (VCDP_LOG2_SESSIONS_PER_THREAD - 2))
#define BIHASH_IP6_MEM_SIZE    (2ULL << 30)

#define BIHASH_TENANT_NUM_BUCKETS (1 << (VCDP_LOG2_TENANTS - 2))
#define BIHASH_TENANT_MEM_SIZE	  (1 << 15)

#define VCDP_DEFAULT_BITMAP (0x1)

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
  VCDP_SESSION_TYPE_IP4,

  /* last */
  VCDP_SESSION_N_TYPES,
} vcdp_session_type_t;

#define foreach_vcdp_session_state                                            \
  _ (FSOL, "embryonic")                                                       \
  _ (ESTABLISHED, "established")                                              \
  _ (TIME_WAIT, "time-wait")

typedef enum
{
#define _(val, str) VCDP_SESSION_STATE_##val,
  foreach_vcdp_session_state
#undef _
    VCDP_SESSION_N_STATE
} vcdp_session_state_t;

#define foreach_vcdp_flow_counter _ (LOOKUP, "lookup")

typedef enum
{
#define _(x, y) VCDP_FLOW_COUNTER_##x,
  foreach_vcdp_flow_counter
#undef _
    VCDP_FLOW_N_COUNTER
} vcdp_flow_counter_index_t;

#define foreach_vcdp_tenant_session_counter                                   \
  _ (CREATED, "created")                                                      \
  _ (REMOVED, "removed")

#define foreach_vcdp_tenant_data_counter                                      \
  _ (INCOMING, "incoming")                                                    \
  _ (OUTGOING, "outgoing")

typedef enum
{
#define _(x, y) VCDP_TENANT_SESSION_COUNTER_##x,
  foreach_vcdp_tenant_session_counter
#undef _
    VCDP_TENANT_SESSION_N_COUNTER
} vcdp_tenant_session_counter_index_t;

typedef enum
{
#define _(x, y) VCDP_TENANT_DATA_COUNTER_##x,
  foreach_vcdp_tenant_data_counter
#undef _
    VCDP_TENANT_DATA_N_COUNTER
} vcdp_tenant_data_counter_index_t;

typedef u16 session_version_t;

enum
{
  VCDP_FLOW_FORWARD = 0,
  VCDP_FLOW_REVERSE = 1,
  VCDP_FLOW_F_B_N = 2
};

enum
{
  VCDP_PACKET_ORIGINAL = 0,
  VCDP_PACKET_NORMALISED = 1
};

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
} __clib_packed vcdp_ip4_key_t;
STATIC_ASSERT_SIZEOF (vcdp_ip4_key_t, 16);

typedef struct
{
  vcdp_ip4_key_t ip4_key;

  union
  {
    struct
    {
      u32 tenant_id;
      u8 zeros[4];
    };
    u64 as_u64;
  };
} __clib_packed vcdp_session_ip4_key_t;
STATIC_ASSERT_SIZEOF (vcdp_session_ip4_key_t, 24);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cache0);
  u32 bitmaps[VCDP_FLOW_F_B_N];
  u64 session_id;
  f64 next_expiration;
  u32 timer_handle;
  session_version_t session_version;
  u8 state; /* see vcdp_session_state_t */
  u8 unused0[31];
  CLIB_CACHE_LINE_ALIGN_MARK (cache1);
  vcdp_session_ip4_key_t key;
  u8 pseudo_dir;
  u8 type; /* see vcdp_session_type_t */
  u8 unused1[36];
} vcdp_session_t; /* TODO: optimise mem layout, this is bad */
STATIC_ASSERT_SIZEOF (vcdp_session_t, 128);

typedef struct
{
  vcdp_session_t *sessions; /* fixed pool */
  vcdp_tw_t wheel;
  f64 current_time;
  u64 session_id_ctr;
  u64 session_id_template;
  u32 *expired_sessions;
  vlib_combined_counter_main_t per_session_ctr[VCDP_FLOW_N_COUNTER];
} vcdp_per_thread_data_t;

typedef struct
{
  u32 tenant_id;
  u32 bitmaps[VCDP_FLOW_F_B_N];
} vcdp_tenant_t;

typedef struct
{
  /* key = (u64) tenant_id; val= (u64) tenant_idx; */
  clib_bihash_8_8_t tenant_idx_by_id;

  /* (gw_session_ip4_key_t) -> (thread_index(32 MSB),session_index(31 bits),
   * stored_direction (1 LSB)) */
  clib_bihash_24_8_t table4;
  clib_bihash_8_8_t session_index_by_id;
  u32 frame_queue_index;
  u64 session_id_ctr_mask;
  vlib_simple_counter_main_t tenant_session_ctr[VCDP_TENANT_SESSION_N_COUNTER];
  vlib_combined_counter_main_t tenant_data_ctr[VCDP_TENANT_DATA_N_COUNTER];

  /* pool of tenants */
  vcdp_tenant_t *tenants;

  /* per-thread data */
  vcdp_per_thread_data_t *per_thread_data;

} vcdp_main_t;

extern vcdp_main_t vcdp_main;
extern vlib_node_registration_t vcdp_handoff_node;

format_function_t format_vcdp_session;
format_function_t format_vcdp_session_detail;
format_function_t format_vcdp_session_state;

static_always_inline u32
vcdp_session_index_from_lookup (u64 val)
{
  return (val & (~(u32) 0)) >> 1;
}

static_always_inline u32
vcdp_thread_index_from_lookup (u64 val)
{
  return val >> 32;
}

static_always_inline u32
vcdp_packet_dir_from_lookup (u64 val)
{
  return val & 0x1;
}

static_always_inline u32
vcdp_pseudo_flow_index_from_lookup (u64 val)
{
  return val & (~(u32) 0);
}

static_always_inline u64
vcdp_session_mk_table_value (u32 thread_index, u32 pseudo_flow_index)
{
  return ((u64) thread_index << 32) | pseudo_flow_index;
}

static_always_inline vcdp_session_t *
vcdp_session_at_index (vcdp_per_thread_data_t *ptd, u32 idx)
{
  return pool_elt_at_index (ptd->sessions, idx);
}

static_always_inline u32
vcdp_mk_flow_index (u32 session_index, u8 dir)
{
  return (session_index << 1) | !(dir == VCDP_FLOW_FORWARD);
}

static_always_inline u32
vcdp_session_from_flow_index (u32 flow_index)
{
  return flow_index >> 1;
}

static_always_inline u32
vcdp_direction_from_flow_index (u32 flow_index)
{
  return (flow_index & 0x1);
}

static_always_inline vcdp_tenant_t *
vcdp_tenant_at_index (vcdp_main_t *vcdpm, u32 idx)
{
  return pool_elt_at_index (vcdpm->tenants, idx);
}

clib_error_t *vcdp_tenant_add_del (vcdp_main_t *vcdp, u32 tenant_id,
				   u8 is_del);
clib_error_t *vcdp_set_services (vcdp_main_t *vcdp, u32 tenant_id, u32 bitmap,
				 u8 direction);
#define VCDP_GW_PLUGIN_BUILD_VER "1.0"

#endif /* __included_vcdp_h__ */
