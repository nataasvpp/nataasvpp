// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_h
#define included_vcdp_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_8_8.h>

#include <vppinfra/tw_timer_2t_1w_2048sl.h>
#include <vppinfra/format_table.h>

#include <vcdp/timer/timer.h>

#define VCDP_LOG2_SESSIONS_PER_THREAD 19
#define VCDP_LOG2_TENANTS             15
#define VCDP_SESSION_ID_TOTAL_BITS    64
#define VCDP_SESSION_ID_EPOCH_N_BITS  16
#define BIHASH_IP4_NUM_BUCKETS        (1 << (VCDP_LOG2_SESSIONS_PER_THREAD - 2))
#define BIHASH_IP4_MEM_SIZE           (2ULL << 30)

#define BIHASH_IP6_NUM_BUCKETS (1 << (VCDP_LOG2_SESSIONS_PER_THREAD - 2))
#define BIHASH_IP6_MEM_SIZE    (2ULL << 30)

#define BIHASH_TENANT_NUM_BUCKETS (1 << (VCDP_LOG2_TENANTS - 2))
#define BIHASH_TENANT_MEM_SIZE    (1 << 15)

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

typedef enum {
  VCDP_SESSION_TYPE_IP4,
  VCDP_SESSION_TYPE_IP6,
  /* last */
  VCDP_SESSION_N_TYPES,
} vcdp_session_type_t;

#define foreach_vcdp_session_state                                                                                     \
  _(FSOL, "embryonic")                                                                                                 \
  _(ESTABLISHED, "established")                                                                                        \
  _(TIME_WAIT, "time-wait")

typedef enum {
#define _(val, str) VCDP_SESSION_STATE_##val,
  foreach_vcdp_session_state
#undef _
    VCDP_SESSION_N_STATE
} vcdp_session_state_t;

#define foreach_vcdp_flow_counter _(LOOKUP, "lookup")

typedef enum {
#define _(x, y) VCDP_FLOW_COUNTER_##x,
  foreach_vcdp_flow_counter
#undef _
    VCDP_FLOW_N_COUNTER
} vcdp_flow_counter_index_t;

#define foreach_vcdp_tenant_session_counter                                                                            \
  _(CREATED, "created", "created sessions")                                                                            \
  _(REMOVED, "removed", "removed sessions")

#define foreach_vcdp_tenant_data_counter                                                                               \
  _(INCOMING, "incoming", "incoming data into tenant")                                                                 \
  _(OUTGOING, "outgoing", "outgoing data out of tenant")

typedef enum {
#define _(x, y, z) VCDP_TENANT_SESSION_COUNTER_##x,
  foreach_vcdp_tenant_session_counter
#undef _
    VCDP_TENANT_SESSION_N_COUNTER
} vcdp_tenant_session_counter_index_t;

typedef enum {
#define _(x, y, z) VCDP_TENANT_DATA_COUNTER_##x,
  foreach_vcdp_tenant_data_counter
#undef _
    VCDP_TENANT_DATA_N_COUNTER
} vcdp_tenant_data_counter_index_t;

typedef u16 session_version_t;

enum { VCDP_FLOW_FORWARD = 0, VCDP_FLOW_REVERSE = 1, VCDP_FLOW_F_B_N = 2 };

enum { VCDP_SESSION_KEY_PRIMARY, VCDP_SESSION_KEY_SECONDARY, VCDP_SESSION_N_KEY };
/* Flags to determine key validity in the session */
#define foreach_vcdp_session_key_flag                                                                                  \
  _(PRIMARY_VALID_IP4, 0x1, "primary-valid-ip4")                                                                       \
  _(PRIMARY_VALID_IP6, 0x2, "primary-valid-ip6")                                                                       \
  _(SECONDARY_VALID_IP4, 0x4, "secondary-valid-ip4")                                                                   \
  _(SECONDARY_VALID_IP6, 0x8, "secondary-valid-ip6")

enum {
#define _(x, n, s) VCDP_SESSION_KEY_FLAG_##x = n,
  foreach_vcdp_session_key_flag
#undef _
};

#define foreach_vcdp_sp_node                                                                                           \
  _(IP4_REASS, "error-drop", "sp-ip4-reassembly")                                                                      \
  _(IP6_REASS, "error-drop", "sp-ip6-reassembly")                                                                      \
  _(IP4_UNKNOWN_PROTO, "error-drop", "sp-ip4-unknown-proto")                                                           \
  _(IP6_UNKNOWN_PROTO, "error-drop", "sp-ip6-unknown-proto")                                                           \
  _(IP4_ICMP4_ERROR, "error-drop", "sp-ip4-icmp4-error")                                                               \
  _(IP6_ICMP6_ERROR, "error-drop", "sp-ip4-icmp6-error")

enum {
#define _(name, val, str) VCDP_SP_NODE_##name,
  foreach_vcdp_sp_node
#undef _
    VCDP_N_SP_NODES
};

typedef union {
  struct {
    union {
      u32 spi;
      struct {
        u16 port_lo;
        u16 port_hi;
      };
    };
    u8 unused;
    u8 proto;
    u16 unused2;
    u32 ip_addr_lo;
    u32 ip_addr_hi;
  };
  u8x16u as_u8x16;
  u32x4u as_u32x4;
  u64x2u as_u64x2;
} __clib_packed vcdp_ip4_key_t;
STATIC_ASSERT_SIZEOF(vcdp_ip4_key_t, 16);

typedef union {
  struct {
    union {
      u32 spi;
      struct {
        u16 port_lo;
        u16 port_hi;
      };
    };
    u16 unused;
    u8 proto;
    u8 unused2;
    ip6_address_t ip6_addr_lo;
    ip6_address_t ip6_addr_hi;
  };
  struct {
    u32x2u as_u32x2;
    u32x8u as_u32x8;
  };
  struct {
    u16x4u as_u16x4;
    u16x16u as_u16x16;
  };
  struct {
    u8x8u as_u8x8;
    u8x16u as_u8x16[2];
  };
  struct {
    u64 as_u64;
    u64x4u as_u64x4;
  };
} __clib_packed vcdp_ip6_key_t;
STATIC_ASSERT_SIZEOF(vcdp_ip6_key_t, 40);

typedef struct {
  vcdp_ip4_key_t ip4_key;

  union {
    struct {
      u32 context_id;
      u8 zeros[4];
    };
    u64 as_u64;
  };
} __clib_packed vcdp_session_ip4_key_t;
STATIC_ASSERT_SIZEOF(vcdp_session_ip4_key_t, 24);

typedef struct {
  vcdp_ip6_key_t ip6_key;

  union {
    struct {
      u32 context_id;
      u8 zeros[4];
    };
    u64 as_u64;
  };
} __clib_packed vcdp_session_ip6_key_t;
STATIC_ASSERT_SIZEOF(vcdp_session_ip6_key_t, 48);

typedef union {
  vcdp_session_ip4_key_t key4;
  vcdp_session_ip6_key_t key6;
} vcdp_session_ip46_key_t;

typedef union {
  vcdp_ip4_key_t key4;
  vcdp_ip6_key_t key6;
} vcdp_ip46_key_t;

typedef union {
  clib_bihash_kv_24_8_t kv4;
  clib_bihash_kv_48_8_t kv6;
} vcdp_bihash_kv46_t;

#define VCDP_SESSION_IP46_KEYS_TYPE(n)                                                                                 \
  union {                                                                                                              \
    vcdp_session_ip4_key_t keys4[(n)];                                                                                 \
    vcdp_session_ip6_key_t keys6[(n)];                                                                                 \
  }

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache0);
  u32 bitmaps[VCDP_FLOW_F_B_N];
  u64 session_id;
  vcdp_session_timer_t timer;
  session_version_t session_version;
  u8 state; /* see vcdp_session_state_t */
  u8 proto;
  u16 tenant_idx;
  u8 unused0[28];
  CLIB_CACHE_LINE_ALIGN_MARK(cache1);

  vcdp_session_ip46_key_t keys[VCDP_SESSION_N_KEY];

  u8 pseudo_dir[VCDP_SESSION_N_KEY];
  u8 type; /* see vcdp_session_type_t */
  u8 key_flags;
  u8 unused1[24];
  u32 rx_id;      // Session originator identifier (tunnel id, sw_if_index)
} vcdp_session_t; /* TODO: optimise mem layout, this is bad */
STATIC_ASSERT_SIZEOF(vcdp_session_t, 256);

typedef struct {
  vcdp_session_t *sessions; /* fixed pool */
  vcdp_tw_t wheel;
  f64 current_time;
  u64 session_id_ctr;
  u64 session_id_template;
  u32 *expired_sessions;
  vlib_combined_counter_main_t per_session_ctr[VCDP_FLOW_N_COUNTER]; // TODO: Shouldn't be here
} vcdp_per_thread_data_t;

typedef enum {
  VCDP_TENANT_FLAG_NO_CREATE = 1 << 1,
} vcdp_tenant_flags_t;

typedef struct {
  u32 tenant_id;
  u32 context_id;
  u32 bitmaps[VCDP_FLOW_F_B_N];
  u32 timeouts[VCDP_N_TIMEOUT];
  u32 sp_node_indices[VCDP_N_SP_NODES];
  uword icmp4_lookup_next; // TODO: Remove?
  uword icmp6_lookup_next; // TODO: Remove?
  vcdp_tenant_flags_t flags;

} vcdp_tenant_t;

typedef struct {
  /* key = (u64) tenant_id; val= (u64) tenant_idx; */
  clib_bihash_8_8_t tenant_idx_by_id;

  /* (gw_session_ip4_key_t) -> (thread_index(32 MSB),session_index(31 bits),
   * stored_direction (1 LSB)) */
  clib_bihash_24_8_t table4;
  clib_bihash_48_8_t table6;
  clib_bihash_8_8_t session_index_by_id;
  u32 frame_queue_index;
  u32 icmp4_error_frame_queue_index; // TODO: Remove
  u32 icmp6_error_frame_queue_index; // TODO: Remove
  u64 session_id_ctr_mask;
  vlib_simple_counter_main_t tenant_session_ctr[VCDP_TENANT_SESSION_N_COUNTER];
  vlib_combined_counter_main_t tenant_data_ctr[VCDP_TENANT_DATA_N_COUNTER];

  /* pool of tenants */
  vcdp_tenant_t *tenants;

  /* per-thread data */
  vcdp_per_thread_data_t *per_thread_data;
  u16 msg_id_base;

  /* Shallow Virtual Reassembly */
  u16 ip4_sv_reass_next_index;
  u16 ip6_sv_reass_next_index;
} vcdp_main_t;

extern vcdp_main_t vcdp_main;
extern vlib_node_registration_t vcdp_handoff_node;
extern vlib_node_registration_t vcdp_lookup_ip4_icmp_node; // TODO: Remove
extern vlib_node_registration_t vcdp_lookup_ip6_icmp_node; // TODO: Remove
extern vlib_node_registration_t vcdp_lookup_ip4_node;
extern vlib_node_registration_t vcdp_lookup_ip6_node;
format_function_t format_vcdp_session;
format_function_t format_vcdp_session_detail;
format_function_t format_vcdp_session_state;
format_function_t format_vcdp_session_type;
format_function_t format_vcdp_tenant;
format_function_t format_vcdp_tenant_extra;
format_function_t format_vcdp_sp_node;
unformat_function_t unformat_vcdp_service;
unformat_function_t unformat_vcdp_service_bitmap;
unformat_function_t unformat_vcdp_sp_node;

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

vcdp_tenant_t *
vcdp_tenant_get_by_id(u32 tenant_id, u16 *tenant_idx);

static_always_inline u8
vcdp_session_n_keys(vcdp_session_t *session)
{
  if (session->key_flags & (VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4 | VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6))
    return 2;
  else
    return 1;
}

static_always_inline int
vcdp_create_session_inline(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_tenant_t *tenant, u16 tenant_idx,
                           u32 thread_index, f64 time_now, void *k, u64 *h, u64 *lookup_val, int is_ipv6, u32 rx_id)
{
  vcdp_bihash_kv46_t kv = {};
  clib_bihash_kv_8_8_t kv2;
  u64 value;
  u8 proto;
  vcdp_session_t *session;
  u32 session_idx;
  u32 pseudo_flow_idx;
  u64 session_id;
  pool_get(ptd->sessions, session);
  session_idx = session - ptd->sessions;
  pseudo_flow_idx = (lookup_val[0] & 0x1) | (session_idx << 1);
  value = vcdp_session_mk_table_value(thread_index, pseudo_flow_idx);
  ;
  if (is_ipv6) {
    clib_memcpy_fast(&kv.kv6.key, k, sizeof(kv.kv6.key));
    kv.kv6.value = value;
    proto = ((vcdp_session_ip6_key_t *) k)->ip6_key.proto;
    if (clib_bihash_add_del_48_8(&vcdp->table6, &kv.kv6, 2)) {
      /* colision - remote thread created same entry */
      pool_put(ptd->sessions, session);
      return 1;
    }
    session->type = VCDP_SESSION_TYPE_IP6;
    session->key_flags = VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6;
  } else {
    clib_memcpy_fast(&kv.kv4.key, k, sizeof(kv.kv4.key));
    kv.kv4.value = value;
    proto = ((vcdp_session_ip4_key_t *) k)->ip4_key.proto;
    if (clib_bihash_add_del_24_8(&vcdp->table4, &kv.kv4, 2)) {
      /* colision - remote thread created same entry */
      pool_put(ptd->sessions, session);
      return 1;
    }
    session->type = VCDP_SESSION_TYPE_IP4;
    session->key_flags = VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4;
  }
  session->session_version += 1;
  session_id = (ptd->session_id_ctr & (vcdp->session_id_ctr_mask)) | ptd->session_id_template;
  ptd->session_id_ctr += 2; /* two at a time, because last bit is reserved for direction */
  session->session_id = session_id;
  session->tenant_idx = tenant_idx;
  session->rx_id = rx_id;

  session->state = VCDP_SESSION_STATE_FSOL;
  kv2.key = session_id;
  kv2.value = value;
  clib_bihash_add_del_8_8(&vcdp->session_index_by_id, &kv2, 1);
  clib_memcpy_fast(session->bitmaps, tenant->bitmaps, sizeof(session->bitmaps));
  if (is_ipv6)
    clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_PRIMARY].key6, k, sizeof(session->keys[0].key6));
  else
    clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_PRIMARY].key4, k, sizeof(session->keys[0].key4));
  session->pseudo_dir[VCDP_SESSION_KEY_PRIMARY] = lookup_val[0] & 0x1;
  session->proto = proto;

  vcdp_session_timer_start(&ptd->wheel, &session->timer, session_idx, time_now,
                           tenant->timeouts[VCDP_TIMEOUT_EMBRYONIC]);

  lookup_val[0] ^= value;
  /* Bidirectional counter zeroing */
  vlib_zero_combined_counter(&ptd->per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP], lookup_val[0]);
  vlib_zero_combined_counter(&ptd->per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP], lookup_val[0] | 0x1);
  vlib_increment_simple_counter(&vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_CREATED], thread_index,
                                tenant_idx, 1);
  return 0;
}

int
vcdp_create_session(vlib_main_t *vm, vlib_buffer_t *b, u32 context_id, u32 thread_index, u32 tenant_index,
                    u32 *session_index, int is_ipv6);

clib_error_t *
vcdp_tenant_add_del(vcdp_main_t *vcdp, u32 tenant_id, u32 context_id, vcdp_tenant_flags_t flags, u8 is_del);
clib_error_t *
vcdp_set_services(vcdp_main_t *vcdp, u32 tenant_id, u32 bitmap, u8 direction);
clib_error_t *
vcdp_set_timeout(vcdp_main_t *vcdp, u32 tenant_id, u32 timeout_idx, u32 timeout_val);

clib_error_t *
vcdp_set_sp_node(vcdp_main_t *vcdp, u32 tenant_id, u32 sp_index, u32 node_index);
clib_error_t *
vcdp_set_icmp_error_node(vcdp_main_t *vcdp, u32 tenant_id, u8 is_ip6, u32 node_index);
void
vcdp_normalise_ip4_key(vcdp_session_t *session, vcdp_session_ip4_key_t *result, u8 key_idx);

void
vcdp_normalise_ip6_key(vcdp_session_t *session, vcdp_session_ip6_key_t *result, u8 key_idx);

u32
vcdp_table_format_insert_session(table_t *t, u32 n, u32 session_index, vcdp_session_t *session, u32 tenant_id, f64 now);
int
vcdp_bihash_add_del_inline_with_hash_24_8(clib_bihash_24_8_t *h, clib_bihash_kv_24_8_t *kv, u64 hash, u8 is_add);

int
vcdp_bihash_add_del_inline_with_hash_48_8(clib_bihash_48_8_t *h, clib_bihash_kv_48_8_t *kv, u64 hash, u8 is_add);

#define VCDP_CORE_PLUGIN_BUILD_VER "1.0"

#endif /* __included_vcdp_h__ */
