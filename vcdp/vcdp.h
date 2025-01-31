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

#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_40_8.h>

#include <vppinfra/format_table.h>
#include <vppinfra/dlist.h>

#include <vcdp/vcdp_counter.json.h>

#include <vcdp/vcdp_types.api_types.h> /* Generated from vcdp_types.api */

/* logging */
#define vcdp_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, vcdp_main.log_class, __VA_ARGS__)
#define vcdp_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, vcdp_main.log_class, __VA_ARGS__)
#define vcdp_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, vcdp_main.log_class, __VA_ARGS__)
#define vcdp_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, vcdp_main.log_class, __VA_ARGS__)
#define vcdp_log_debug(...)\
  vlib_log(VLIB_LOG_LEVEL_DEBUG, vcdp_main.log_class, __VA_ARGS__)


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

#define VCDP_TENANT_INVALID_IDX (65535)

typedef enum vcdp_session_type : u8 {
  VCDP_SESSION_TYPE_IP4,
  VCDP_SESSION_TYPE_IP6,
  VCDP_SESSION_TYPE_NAT64,
  /* last */
  VCDP_SESSION_N_TYPES,
} vcdp_session_type_t;

#define foreach_vcdp_session_state                                                                                     \
  _(FSOL, "embryonic")                                                                                                 \
  _(ESTABLISHED, "established")                                                                                        \
  _(TIME_WAIT, "time-wait")                                                                                            \
  _(STATIC, "static")

typedef enum vcdp_session_state : u8 {
#define _(val, str) VCDP_SESSION_STATE_##val,
  foreach_vcdp_session_state
#undef _
    VCDP_SESSION_N_STATE
} vcdp_session_state_t;

typedef u16 session_version_t;

typedef enum {
   VCDP_FLOW_FORWARD = 0,
   VCDP_FLOW_REVERSE = 1,
   VCDP_FLOW_F_B_N = 2,
} vcdp_session_direction_t;

enum {
  VCDP_SESSION_KEY_PRIMARY = 0,
  VCDP_SESSION_KEY_SECONDARY = 1,
  VCDP_SESSION_N_KEY = 2,
};

typedef struct __attribute__((packed)) {
  ip46_address_t src;
  ip46_address_t dst;
  u32 proto : 8;
  u32 context_id : 24;
  u16 sport;
  u16 dport;
} vcdp_session_key_t;
_Static_assert(sizeof(vcdp_session_key_t) == 40, "Size of vcdp_session_key_t should be 64");

typedef struct {
  /* First cache line (64 bytes) */
  CLIB_CACHE_LINE_ALIGN_MARK(cache0);
  u64 bytes[VCDP_FLOW_F_B_N];        // 16
  u32 pkts[VCDP_FLOW_F_B_N];         // 8
  u32 bitmaps[VCDP_FLOW_F_B_N];      // 8
  u32 last_heard;                    // 4
  vcdp_session_timer_t timer;        // 16
  u32 rx_id;                         // 4
  u16 tenant_idx;                    // 2
  session_version_t session_version; // 2
  vcdp_session_state_t state;        // 1

  /* Second cache line (64 bytes) */
  // CLIB_CACHE_LINE_ALIGN_MARK(cache1);

  // Slow-path fields
  u32 thread_index;
  vcdp_session_key_t keys[VCDP_SESSION_N_KEY]; // 80
  u64 session_id;
  u32 created;                       // 4
  vcdp_session_type_t type;          // 1
} vcdp_session_t;
STATIC_ASSERT_SIZEOF(vcdp_session_t, 256);
//char (*__compile_time_check)[sizeof(vcdp_session_t)] = 1;  // This will show actual size
// char (*__compile_time_assert)[128] = 1;  // This will show expected size

// _Static_assert(sizeof(vcdp_session_t) == 128, "Size of vcdp_session_t should be 128");

typedef struct {
  u64 session_id_ctr;
  u64 session_id_template;

  /* LRU session list - head is stale, tail is fresh */
  dlist_elt_t *lru_pool;
  u32 lru_head_index[VCDP_N_TIMEOUT];
} vcdp_per_thread_data_t;

typedef struct {
  u32 tenant_id;
  u32 context_id;
  u32 bitmaps[VCDP_SERVICE_CHAIN_N];
  u32 tcp_bitmaps[VCDP_SERVICE_CHAIN_N];
} vcdp_tenant_t;

typedef struct {
  /* key = (u64) tenant_id; val= (u64) tenant_idx; */
  clib_bihash_8_8_t tenant_idx_by_id;

  /* (gw_session_ip4_key_t) -> (thread_index(32 MSB),session_index(31 bits),
   * stored_direction (1 LSB)) */
  clib_bihash_40_8_t session_hash;
  vcdp_session_t *sessions; /* fixed pool */

  clib_bihash_8_8_t session_index_by_id;

  u32 frame_queue_index;
  u32 frame_queue_icmp_index;
  u64 session_id_ctr_mask;
  vlib_simple_counter_main_t tenant_simple_ctr[VCDP_TENANT_COUNTER_N_SIMPLE];
  vlib_combined_counter_main_t tenant_combined_ctr[VCDP_TENANT_COUNTER_N_COMBINED];

  /* pool of tenants */
  vcdp_tenant_t *tenants;

  /* per-thread data */
  vcdp_per_thread_data_t *per_thread_data;
  u16 msg_id_base;

  u32 timeouts[VCDP_N_TIMEOUT];

    /* log class */
  vlib_log_class_t log_class;
} vcdp_main_t;

typedef struct {
  u32 no_tenants;
  u32 no_sessions;
  u32 no_nat_instances;
  u32 no_tunnels;
} vcdp_cfg_main_t;

enum vcdp_lookup_mode_e {
  VCDP_LOOKUP_MODE_DEFAULT = 0,
  VCDP_LOOKUP_MODE_4TUPLE,
  VCDP_LOOKUP_MODE_3TUPLE,
  VCDP_LOOKUP_MODE_1TUPLE,
};

extern vcdp_main_t vcdp_main;
extern vcdp_cfg_main_t vcdp_cfg_main;
extern vlib_node_registration_t vcdp_handoff_node;
extern vlib_node_registration_t vcdp_lookup_ip4_node;
extern vlib_node_registration_t vcdp_lookup_ip6_node;
extern vlib_node_registration_t vcdp_input_node;
extern vlib_node_registration_t vcdp_icmp_fwd_ip4_node;

format_function_t format_vcdp_session;
format_function_t format_vcdp_session_detail;
format_function_t format_vcdp_session_state;
format_function_t format_vcdp_session_type;
format_function_t format_vcdp_tenant;
format_function_t format_vcdp_tenant_extra;
format_function_t format_vcdp_session_key;
format_function_t format_vcdp_session_ip4_key;
format_function_t format_vcdp_session_ip6_key;
format_function_t format_vcdp_bitmap;
format_function_t format_vcdp_tenant_stats;

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
vcdp_session_at_index(vcdp_main_t *vcdp, u32 idx)
{
  return pool_elt_at_index(vcdp->sessions, idx);
}

static_always_inline vcdp_session_t *
vcdp_session_at_index_check(vcdp_main_t *vcdp, u32 idx)
{
  if (pool_is_free_index(vcdp->sessions, idx))
    return 0;
  return pool_elt_at_index(vcdp->sessions, idx);
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

clib_error_t *vcdp_tenant_add_del(vcdp_main_t *vcdp, u32 tenant_id, u32 context_id, u32 default_tenant_id, bool is_add);
clib_error_t *vcdp_set_services(vcdp_main_t *vcdp, u32 tenant_id, u32 bitmap, vl_api_vcdp_service_chain_t direction);
clib_error_t *vcdp_set_timeout(vcdp_main_t *vcdp, u32 timeouts[]);

u32 vcdp_table_format_insert_session(table_t *t, u32 n, u32 session_index, vcdp_session_t *session, u32 tenant_id, f64 now);
u32 vcdp_calc_bihash_buckets (u32 n_elts);
u16 vcdp_tenant_idx_by_id(u32 tenant_id);
vcdp_session_t *vcdp_create_session(u16 tenant_idx, vcdp_session_key_t *primary, vcdp_session_key_t *secondary,
                                    bool is_static, u32 *flow_index);
vcdp_session_t *vcdp_lookup_session(u32 context_id, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst,
                                    u16 dport);
void vcdp_session_clear(void);
int vcdp_session_try_add_secondary_key(vcdp_main_t *vcdp, u32 thread_index,
                                       u32 pseudo_flow_index, vcdp_session_key_t *key);
void vcdp_session_remove(vcdp_main_t *vcdp, vcdp_session_t *session, u32 thread_index,
                         u32 session_index);
void vcdp_session_remove_no_timer(vcdp_main_t *vcdp, vcdp_session_t *session, u32 thread_index,
                         u32 session_index);
bool vcdp_session_is_expired(vcdp_session_t *session, f64 time_now);
void vcdp_session_reopen(vcdp_main_t *vcdp, u32 thread_index, vcdp_session_t *session);
int vcdp_lookup_with_hash(u64 hash, vcdp_session_key_t *k, u64 *v);
int vcdp_lookup(vcdp_session_key_t *k, u64 *v);

#endif
