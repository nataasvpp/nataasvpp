// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_nat_h
#define included_nat_h

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vnet/ip/ip46_address.h>

#define NAT_INVALID_TENANT_IDX  (u16)(~0)
#define NAT_ALLOC_POOL_ARRAY_SZ 13

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

#define foreach_nat_rewrite_op                                                                                         \
  _(SADDR, 0x1, "src-addr")                                                                                            \
  _(SPORT, 0x2, "src-port")                                                                                            \
  _(DADDR, 0x4, "dst-addr")                                                                                            \
  _(DPORT, 0x8, "dst-port")                                                                                            \
  _(ICMP_ID, 0x10, "icmp-id")                                                                                          \
  _(TXFIB, 0x20, "tx-fib")

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
} nat_rewrite_data_t;
STATIC_ASSERT_SIZEOF(nat_rewrite_data_t, CLIB_CACHE_LINE_BYTES);

typedef struct {
  nat_rewrite_data_t *flows; /* by flow_index */
} nat_per_thread_data_t;

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache0);
  u16 flags;
  u16 num;
  ip4_address_t addr[NAT_ALLOC_POOL_ARRAY_SZ];
  ip4_address_t *remaining;
} nat_alloc_pool_t;
STATIC_ASSERT_SIZEOF(nat_alloc_pool_t, CLIB_CACHE_LINE_BYTES);

typedef struct {
  nat_tenant_t *tenants;        /* vec */
  nat_alloc_pool_t *alloc_pool; /* pool of allocation pools */
  nat_per_thread_data_t *ptd;   /* vec */
  uword *alloc_pool_idx_by_id;  /* hash */
  u16 msg_id_base;
} nat_main_t;

extern nat_main_t nat_main;

clib_error_t *
nat_alloc_pool_add_del(nat_main_t *nat, u32 alloc_pool_id, u8 is_del, ip4_address_t *addr);

clib_error_t *
nat_tenant_set_snat(nat_main_t *nat, u32 tenant_id, u32 alloc_pool_id, u8 unset);
format_function_t format_vcdp_nat_rewrite;

#endif
