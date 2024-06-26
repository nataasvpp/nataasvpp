// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_h
#define included_vcdp_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_8_8.h>

#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>
#include <vppinfra/format_table.h>

#include <vcdp/vcdp_counter.json.h>

#define VCDP_DEBUG  0
#if VCDP_DEBUG > 0
#define VCDP_DBG(_lvl, _fmt, _args...)   \
  if (_lvl <= VCDP_DEBUG)                \
    clib_warning (_fmt, ##_args)
#else
#define VCDP_DBG(_lvl, _fmt, _args...)
#endif

#include <vcdp/timer.h>

// TODO: Make this configurable on startup
#define VCDP_SESSION_ID_TOTAL_BITS    64
#define VCDP_SESSION_ID_EPOCH_N_BITS  16

/* Convention session_index is 31 bit
 * Flow_index (embedded in vlib_buffer_t as "flow_id")
 * Flow_index = (session_index << 1) + !(is_forward)
 * A flow is "forward" if it's going from initiator to responder.
 * Compared to upstream VCDP, no normalisation is done.
 * Reverse direction always uses secondary key.
 */

typedef enum {
  VCDP_SESSION_TYPE_IP4,
  /* last */
  VCDP_SESSION_N_TYPES,
} vcdp_session_type_t;

#define foreach_vcdp_session_state                                                                                     \
  _(FSOL, "embryonic")                                                                                                 \
  _(ESTABLISHED, "established")                                                                                        \
  _(TIME_WAIT, "time-wait")                                                                                            \
  _(STATIC, "static")

typedef enum {
#define _(val, str) VCDP_SESSION_STATE_##val,
  foreach_vcdp_session_state
#undef _
    VCDP_SESSION_N_STATE
} vcdp_session_state_t;

typedef u16 session_version_t;

typedef enum {
   VCDP_FLOW_FORWARD = 0,
   VCDP_FLOW_REVERSE = 1,
   VCDP_FLOW_F_B_N = 2
} vcdp_session_direction_t;

enum { VCDP_SESSION_KEY_PRIMARY, VCDP_SESSION_KEY_SECONDARY, VCDP_SESSION_N_KEY };
/* Flags to determine key validity in the session */
#define foreach_vcdp_session_key_flag                                                                                  \
  _(PRIMARY_VALID_IP4, 0x1, "primary-valid-ip4")                                                                       \
  _(SECONDARY_VALID_IP4, 0x4, "secondary-valid-ip4")

enum {
#define _(x, n, s) VCDP_SESSION_KEY_FLAG_##x = n,
  foreach_vcdp_session_key_flag
#undef _
};

typedef union {
  struct {
    u32 src, dst;
    u16 sport, dport;
    u32 context_id : 24;
    u8 proto : 8;
  };
  u64 as_u64[2];
} __clib_packed vcdp_session_ip4_key_t;
STATIC_ASSERT_SIZEOF(vcdp_session_ip4_key_t, 16);

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache0);
  u32 bitmaps[VCDP_FLOW_F_B_N]; // 8
  u64 session_id;               // 8
  vcdp_session_timer_t timer;   // 12
  u32 rx_id;      // Session originator identifier (tunnel id, sw_if_index)  // 4
  vcdp_session_ip4_key_t keys[VCDP_SESSION_N_KEY]; //32

  u64 bytes[VCDP_FLOW_F_B_N];   // 16
  u32 pkts[VCDP_FLOW_F_B_N];    // 8
  session_version_t session_version;    // 2
  u16 tenant_idx;               // 2
  u8 state; /* see vcdp_session_state_t */ // 1
  u8 proto;                     // 1 TODO: Needed?
  u8 type; /* see vcdp_session_type_t */ // 1
  u8 key_flags;                 // 1
} vcdp_session_t; /* TODO: optimise mem layout */
STATIC_ASSERT_SIZEOF(vcdp_session_t, 128);

typedef struct {
  vcdp_session_t *sessions; /* fixed pool */
  vcdp_tw_t wheel;
  f64 current_time;
  u64 session_id_ctr;
  u64 session_id_template;
  u32 *expired_sessions;
} vcdp_per_thread_data_t;

typedef enum {
  VCDP_TENANT_FLAG_NO_CREATE = 1 << 0,
} vcdp_tenant_flags_t;

typedef struct {
  u32 tenant_id;
  u32 context_id;
  u32 bitmaps[VCDP_FLOW_F_B_N];
  u32 timeouts[VCDP_N_TIMEOUT];
  vcdp_tenant_flags_t flags;
} vcdp_tenant_t;

typedef struct {
  /* key = (u64) tenant_id; val= (u64) tenant_idx; */
  clib_bihash_8_8_t tenant_idx_by_id;

  /* (gw_session_ip4_key_t) -> (thread_index(32 MSB),session_index(31 bits),
   * stored_direction (1 LSB)) */
  clib_bihash_16_8_t table4;
  clib_bihash_8_8_t session_index_by_id;
  u32 frame_queue_index;
  u64 session_id_ctr_mask;
  vlib_simple_counter_main_t tenant_simple_ctr[VCDP_TENANT_COUNTER_N_SIMPLE];
  vlib_combined_counter_main_t tenant_combined_ctr[VCDP_TENANT_COUNTER_N_COMBINED];

  /* pool of tenants */
  vcdp_tenant_t *tenants;

  /* per-thread data */
  vcdp_per_thread_data_t *per_thread_data;
  u16 msg_id_base;

  u32 icmp_error_node_index;
} vcdp_main_t;

typedef struct {
  u32 no_tenants;
  u32 no_sessions_per_thread;
  u32 no_nat_instances;
  u32 no_tunnels;
} vcdp_cfg_main_t;

extern vcdp_main_t vcdp_main;
extern vcdp_cfg_main_t vcdp_cfg_main;
extern vlib_node_registration_t vcdp_handoff_node;
extern vlib_node_registration_t vcdp_lookup_ip4_node;
extern vlib_node_registration_t vcdp_input_node;

format_function_t format_vcdp_session;
format_function_t format_vcdp_session_detail;
format_function_t format_vcdp_session_state;
format_function_t format_vcdp_session_type;
format_function_t format_vcdp_tenant;
format_function_t format_vcdp_tenant_extra;
format_function_t format_vcdp_session_key;
format_function_t format_vcdp_bitmap;
unformat_function_t unformat_vcdp_service;
unformat_function_t unformat_vcdp_service_bitmap;

// TODO: Move this to icmp46_packet.h
typedef struct
{
  u16 identifier;
  u16 sequence;
} icmp_echo_header_t;

static_always_inline u32
vcdp_session_index_from_lookup(u64 val)
{
  return (val & (~(u32) 0)) >> 1;
}

static_always_inline u32
vcdp_thread_index_from_lookup(u64 val)
{
  return val >> 32;
}

static_always_inline u32
vcdp_packet_dir_from_lookup(u64 val)
{
  return val & 0x1;
}

static_always_inline u32
vcdp_pseudo_flow_index_from_lookup(u64 val)
{
  return val & (~(u32) 0);
}

static_always_inline u64
vcdp_session_mk_table_value(u32 thread_index, u32 pseudo_flow_index)
{
  return ((u64) thread_index << 32) | pseudo_flow_index;
}

static_always_inline vcdp_session_t *
vcdp_session_at_index(vcdp_per_thread_data_t *ptd, u32 idx)
{
  return pool_elt_at_index(ptd->sessions, idx);
}

static_always_inline vcdp_session_t *
vcdp_session_at_index_check(vcdp_per_thread_data_t *ptd, u32 idx)
{
  if (pool_is_free_index(ptd->sessions, idx))
    return 0;
  return pool_elt_at_index(ptd->sessions, idx);
}

static_always_inline u32
vcdp_mk_flow_index(u32 session_index, u8 dir)
{
  return (session_index << 1) | !(dir == VCDP_FLOW_FORWARD);
}

static_always_inline u32
vcdp_session_from_flow_index(u32 flow_index)
{
  return flow_index >> 1;
}

static_always_inline u32
vcdp_direction_from_flow_index(u32 flow_index)
{
  return (flow_index & 0x1);
}

static_always_inline vcdp_tenant_t *
vcdp_tenant_at_index(vcdp_main_t *vcdpm, u32 idx)
{
  return pool_elt_at_index(vcdpm->tenants, idx);
}

vcdp_tenant_t *vcdp_tenant_get_by_id(u32 tenant_id, u16 *tenant_idx);

// TODO: Remove
static_always_inline u8
vcdp_session_n_keys(vcdp_session_t *session)
{
  if (session->key_flags & (VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4))
    return 2;
  else
    return 1;
}

clib_error_t *vcdp_tenant_add_del(vcdp_main_t *vcdp, u32 tenant_id, u32 context_id, vcdp_tenant_flags_t flags, u8 is_add);
clib_error_t *vcdp_set_services(vcdp_main_t *vcdp, u32 tenant_id, u32 bitmap, vcdp_session_direction_t direction);
clib_error_t *vcdp_set_timeout(vcdp_main_t *vcdp, u32 tenant_id, u32 timeout_idx, u32 timeout_val);

u32 vcdp_table_format_insert_session(table_t *t, u32 n, u32 session_index, vcdp_session_t *session, u32 tenant_id, f64 now);
int vcdp_bihash_add_del_inline_with_hash_16_8(clib_bihash_16_8_t *h, clib_bihash_kv_16_8_t *kv, u64 hash, u8 is_add);

u16 vcdp_tenant_idx_by_id(u32 tenant_id);
int vcdp_create_session_v4_2(u32 context, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst, u16 dport);
vcdp_session_t *vcdp_lookup_session_v4(u32 tenant_id, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst, u16 dport);
void vcdp_session_clear(void);

#endif
