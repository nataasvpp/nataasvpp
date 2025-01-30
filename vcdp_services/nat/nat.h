// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_nat_h
#define included_nat_h

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vnet/ip/ip46_address.h>
#include <vcdp_services/nat/nat_counter.json.h>
#include <vppinfra/bihash_16_8.h>

#define NAT_INVALID_TENANT_IDX  (u16)(~0)

// TODO: What to do about the flags?
#define foreach_nat_tenant_flag _(SNAT, 0x1, "snat")

enum {
#define _(name, x, str) NAT_TENANT_FLAG_##name = (x),
  foreach_nat_tenant_flag
#undef _
    NAT_TENANT_N_FLAGS
};

typedef struct {
  u16 flags;
  uword out_alloc_pool_idx;
} nat_tenant_t;

typedef struct {
  char nat_id[36+1];
  u32 context_id;
  ip4_address_t *addresses; // vec
} nat_instance_t;

typedef struct {
  char nat_id[36+1];
  u32 sw_if_index;
  u16 *pending_tenant_ids; // awaiting creation of main NAT instance vec
} nat_if_instance_t;

#define foreach_nat_rewrite_op                                                                                         \
  _(SADDR, 0x1, "src-addr")                                                                                            \
  _(SPORT, 0x2, "src-port")                                                                                            \
  _(DADDR, 0x4, "dst-addr")                                                                                            \
  _(DPORT, 0x8, "dst-port")                                                                                            \
  _(ICMP_ID, 0x10, "icmp-id")                                                                                          \
  _(TXFIB, 0x20, "tx-fib")                                                                                             \

typedef enum {
#define _(sym, x, s) NAT_REWRITE_OP_##sym = x,
  foreach_nat_rewrite_op
#undef _
} nat_rewrite_op_t;

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache0);
  struct {
    ip4_address_t saddr, daddr;
    u16 sport;
    u16 dport;
    u32 fib_index;
    u16 icmp_id;
    u8 proto;
  } rewrite;
  nat_rewrite_op_t ops;
  uword l3_csum_delta; // TODO: csum_t?
  uword l4_csum_delta;
  session_version_t version;
  u16 nat_idx; // index into nat_main.instances
} nat_rewrite_data_t;
_Static_assert(sizeof(nat_rewrite_data_t) == CLIB_CACHE_LINE_BYTES, "nat_rewrite_data_t is not cache aligned");

typedef enum {
  NAT64_REWRITE_OP_HDR_64 = 1 << 1,
  NAT64_REWRITE_OP_HDR_46 = 1 << 2,
  NAT64_REWRITE_OP_SPORT = 1 << 3,
  NAT64_REWRITE_OP_DPORT = 1 << 4,
} nat64_rewrite_op_t;

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache0);
  union {
    ip6_header_t ip6;
    ip4_header_t ip4;
  };
  u16 sport;
  u16 dport;
  nat64_rewrite_op_t ops;
  session_version_t version;
  u16 nat_idx; // index into nat_main.instances
} nat64_rewrite_data_t;
// _Static_assert(sizeof(nat64_rewrite_data_t) == CLIB_CACHE_LINE_BYTES, "nat64_rewrite_data_t is not cache aligned");

typedef struct {
  nat_rewrite_data_t *flows; /* by flow_index */
  nat64_rewrite_data_t *flows64; /* by flow_index */
} nat_per_thread_data_t;

#define MAX_THREADS 16
typedef struct {
    // Each thread gets its own port ranges
    struct {
        u16 start_port;
        u16 end_port;
    } thread_port_range[MAX_THREADS];
} nat_port_allocator_t;

/*
 * 3-tuple session key
 */
typedef union {
  struct {
    u8 proto : 8;
    u32 context_id : 24;
    u32 addr;
    u16 port;
  };
  u64 as_u64[2];
} __clib_packed nat_3tuple_ip4_key_t;
STATIC_ASSERT_SIZEOF(nat_3tuple_ip4_key_t, 16);

/*
 * Port-forwarding rewrite template
 */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache0);
  ip46_address_t addr;
  u16 port;
  u32 fib_index;
  nat_rewrite_op_t ops;
  u16 nat_idx; // index into nat_main.instances
  u16 tenant_idx;
} nat_port_forwarding_session_t;

typedef struct {
  nat_instance_t *instances;        /* vec */
  uword *uuid_hash;
  u16 *instance_by_tenant_idx;
  nat_per_thread_data_t *ptd;   /* vec */
  u16 msg_id_base;

  /* Per instance counters */
  clib_spinlock_t counter_lock;
  vlib_simple_counter_main_t simple_counters[VCDP_NAT_COUNTER_N_SIMPLE];
  vlib_combined_counter_main_t combined_counters[VCDP_NAT_COUNTER_N_COMBINED];

  /* Interface pool */
  nat_if_instance_t *if_instances;
  u32 *interface_by_sw_if_index;

  u32 port_retries;

  clib_bihash_16_8_t port_forwarding;
  nat_port_forwarding_session_t *port_forwarding_sessions;

  u32 random_seed;
} nat_main_t;

extern nat_main_t nat_main;

format_function_t format_vcdp_nat_rewrite;
format_function_t format_vcdp_nat64_rewrite;
u8 *format_vcdp_nat_service(u8 *s, u32 thread_index, u32 session_index);
u8 *format_vcdp_nat64_service(u8 *s, u32 thread_index, u32 session_index);

int vcdp_nat_add(char *natid, u32 context_id, ip4_address_t *addr, bool is_if);
int vcdp_nat_if_add(char *nat_id, u32 sw_if_index);
int vcdp_nat_remove(char *nat_id);
int vcdp_nat_bind_set_unset(u32 tenant_id, char *nat_id, bool is_set);
nat_instance_t *vcdp_nat_instance_by_tenant_idx(u16 tenant_idx, u16 *nat_idx);
void vcdp_nat_set_port_retries(u32 port_retries);
int vcdp_nat_port_forwarding(char *nat_id, u32 tenant_id, ip4_address_t *src, u16 sport, u8 proto, ip4_address_t *dst,
                             u16 dport, bool is_add);

#endif
